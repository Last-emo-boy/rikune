#!/usr/bin/env bash
set -euo pipefail

image_ref=${1:?usage: verify-static-container.sh IMAGE}
container_name="rikune-static-contract-${RANDOM}-$$"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test "$(docker image inspect "$image_ref" --format '{{.Config.User}}')" = "1000:1000"
test "$(docker run --rm "$image_ref" id -u)" = 1000
test "$(docker run --rm "$image_ref" id -g)" = 1000

docker run --rm "$image_ref" sh -ceu '
  test ! -e /home/appuser
  test "$(getent passwd appuser | cut -d: -f6)" = /nonexistent
  for target in /app/dist /app/node_modules /app/packages /app/workers /app/src /app/scripts /app/package.json /app/LICENSE /app/DISCLOSURE /app/.rikune-static-profile /app/static-profile.lock.json /docker-entrypoint.sh; do
    test "$(stat -c %u:%g "$target")" = "0:0"
  done
  offender=$(find /app/dist /app/node_modules /app/packages /app/workers /app/src /app/scripts -xdev \( ! -user root -o ! -group root -o \( ! -type l -a -perm /022 \) \) -print -quit)
  test -z "$offender"
  broken_symlink=$(find /app/dist /app/node_modules /app/packages /app/workers /app/src /app/scripts -xdev -type l ! -exec test -e {} \; -print -quit)
  test -z "$broken_symlink"
  symlink_targets=$(find /app/dist /app/node_modules /app/packages /app/workers /app/src /app/scripts -xdev -type l -exec readlink -e -- {} +)
  printf "%s\n" "$symlink_targets" | while IFS= read -r target; do
    test -z "$target" && continue
    case "$target" in
      /app/dist|/app/dist/*|/app/node_modules|/app/node_modules/*|/app/packages|/app/packages/*|/app/workers|/app/workers/*|/app/src|/app/src/*|/app/scripts|/app/scripts/*) ;;
      *) exit 1 ;;
    esac
  done
  test "$(stat -c %a /app/.rikune-static-profile)" = 444
  test "$(stat -c %a /app/static-profile.lock.json)" = 444
  test "$(stat -c %a /app/LICENSE)" = 444
  test "$(stat -c %a /app/DISCLOSURE)" = 444
  test -s /app/LICENSE
  test -s /app/DISCLOSURE
  grep -Fqi dual-use /app/DISCLOSURE
  test "$(stat -c %a /app/scripts/secure-fs-helper.py)" = 555
  test "$(stat -c %a /docker-entrypoint.sh)" = 555
  ! touch /app/dist/.write-probe
  ! touch /app/node_modules/.write-probe
  ! touch /app/src/.write-probe
  for target in /app/workspaces /app/data /app/cache /app/logs /app/storage /app/uploads /ghidra-projects /ghidra-logs /tmp; do
    probe="$target/.contract-write-probe"
    : > "$probe"
    rm -f "$probe"
  done
'

runtime_mounts=(
  --tmpfs "/tmp:rw,noexec,nosuid,uid=1000,gid=1000,mode=1777"
  --tmpfs "/app/workspaces:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/app/data:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/app/cache:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/app/logs:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/app/storage:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/app/uploads:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/ghidra-projects:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
  --tmpfs "/ghidra-logs:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700"
)

docker run -d -i --name "$container_name" --read-only \
  -e API_ENABLED=true -e API_KEY=rikune-static-verification-key \
  --security-opt no-new-privileges:true --cap-drop ALL \
  "${runtime_mounts[@]}" "$image_ref" >/dev/null

ready=false
for _attempt in $(seq 1 90); do
  if ! docker inspect "$container_name" --format '{{.State.Running}}' | grep -qx true; then
    break
  fi
  if docker exec "$container_name" node --input-type=module --eval \
    "const c=new AbortController();const t=setTimeout(()=>c.abort(),1000);try{const r=await fetch('http://127.0.0.1:18080/api/v1/health',{signal:c.signal});process.exit(r.ok?0:1)}catch{process.exit(1)}finally{clearTimeout(t)}"; then
    ready=true
    break
  fi
  sleep 2
done

if [ "$ready" != true ]; then
  docker logs "$container_name" >&2 || true
  echo "static read-only bootstrap did not become healthy" >&2
  exit 1
fi

docker exec "$container_name" node --input-type=module --eval '
  import fs from "node:fs";
  import { spawnSync } from "node:child_process";
  import { resolveSmtWorkerPath } from "/app/dist/plugins/vm-analysis/tools/smt-solve.js";
  import { resolveRizinDiffWorkerPath } from "/app/dist/plugins/binary-diff/binary-diff-engine.js";
  import { loadPatterns } from "/app/dist/plugins/vuln-scanner/vuln-patterns.js";
  import { loadSeedDataIfEmpty } from "/app/dist/plugins/kb-collaboration/kb/seed-loader.js";

  const smtWorker = resolveSmtWorkerPath();
  const diffWorker = resolveRizinDiffWorkerPath();
  for (const worker of [smtWorker, diffWorker]) {
    if (!fs.statSync(worker).isFile()) throw new Error(`missing runtime worker: ${worker}`);
  }

  const patterns = await loadPatterns();
  if (!Array.isArray(patterns.patterns) || patterns.patterns.length === 0) {
    throw new Error("default vulnerability patterns were not loaded");
  }

  let inserted = 0;
  const seedResult = await loadSeedDataIfEmpty({
    queryOneSql: () => ({ count: 0 }),
    runSql: () => { inserted += 1; },
  });
  if (seedResult.loaded === 0 || seedResult.loaded !== inserted) {
    throw new Error("KB seed data was not loaded from the packaged runtime asset");
  }

  const smtRequest = {
    job_id: "static-smoke",
    tool: "solve_constraints",
    params: {
      variables: [{ name: "x", bits: 32 }],
      constraints: [{
        left: { kind: "var", name: "x", bits: 32 },
        op: "==",
        right: { kind: "const", value: 7, bits: 32 },
      }],
    },
  };
  const smt = spawnSync("python", [smtWorker], {
    input: `${JSON.stringify(smtRequest)}\n`,
    encoding: "utf8",
    timeout: 30000,
  });
  if (smt.error || smt.status !== 0) {
    throw new Error(`SMT worker failed to start: ${smt.error?.message ?? smt.stderr}`);
  }
  const smtResponse = JSON.parse(smt.stdout.trim());
  if (!smtResponse.ok || smtResponse.data?.satisfiable !== true || smtResponse.data?.solution?.x !== 7) {
    throw new Error(`SMT worker smoke failed: ${smt.stdout}`);
  }

  const diff = spawnSync("python", [diffWorker], { encoding: "utf8", timeout: 30000 });
  if (diff.error || diff.status !== 1) {
    throw new Error(`binary diff worker did not reach its argument gate: ${diff.error?.message ?? diff.stderr}`);
  }
  const diffResponse = JSON.parse(diff.stdout.trim());
  if (diffResponse.ok !== false || !String(diffResponse.error).includes("Usage:")) {
    throw new Error(`binary diff worker returned an unexpected smoke response: ${diff.stdout}`);
  }
'

docker exec "$container_name" sh -ceu '
  for target in /app/workspaces /app/data /app/cache /app/logs /app/storage /app/uploads /ghidra-projects /ghidra-logs /tmp; do
    probe="$target/.runtime-write-probe"
    : > "$probe"
    rm -f "$probe"
  done
  ! touch /app/dist/.runtime-write-probe
  ! touch /app/node_modules/.runtime-write-probe
  ! touch /app/src/.runtime-write-probe
  test -s /app/data/database.db
'

docker stop --time 35 "$container_name" >/dev/null
docker rm "$container_name" >/dev/null
