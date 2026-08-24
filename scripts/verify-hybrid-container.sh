#!/usr/bin/env bash
set -euo pipefail

image_ref=${1:?usage: verify-hybrid-container.sh IMAGE EXPECTED_REVISION [EXPECTED_VERSION]}
expected_revision=${2:?usage: verify-hybrid-container.sh IMAGE EXPECTED_REVISION [EXPECTED_VERSION]}
expected_version=${3:-1.4.0}
container_name="rikune-hybrid-contract-${RANDOM}-$$"

if [[ ! "$expected_revision" =~ ^[a-f0-9]{40}$ ]]; then
  echo "expected revision must be a 40-character lowercase Git SHA" >&2
  exit 1
fi

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test "$(docker image inspect "$image_ref" --format '{{.Architecture}}/{{.Os}}')" = "amd64/linux"
test "$(docker image inspect "$image_ref" --format '{{.Config.User}}')" = "1000:1000"
test "$(docker image inspect "$image_ref" --format '{{json .Config.Entrypoint}}')" = '["/docker-entrypoint.sh"]'
test "$(docker image inspect "$image_ref" --format '{{json .Config.Cmd}}')" = '["node","dist/index.js"]'
test "$(docker image inspect "$image_ref" --format '{{.Config.WorkingDir}}')" = "/app"
test "$(docker image inspect "$image_ref" --format '{{index .Config.Labels "org.opencontainers.image.rikune.profile"}}')" = "hybrid"
test "$(docker image inspect "$image_ref" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = "$expected_revision"
test "$(docker image inspect "$image_ref" --format '{{index .Config.Labels "org.opencontainers.image.version"}}')" = "$expected_version"
test "$(docker image inspect "$image_ref" --format '{{index .Config.Labels "version"}}')" = "$expected_version"

image_environment=$(docker image inspect "$image_ref" --format '{{range .Config.Env}}{{println .}}{{end}}')
for required_environment in \
  NODE_ENV=production \
  RUNNING_IN_DOCKER=true \
  API_ENABLED=false \
  WORKSPACE_ROOT=/app/workspaces \
  DB_PATH=/app/data/database.db \
  CACHE_ROOT=/app/cache \
  HOME=/tmp/rikune-home; do
  grep -Fxq "$required_environment" <<<"$image_environment"
done
if grep -Eq '^(RUNTIME_HOST_AGENT_ENDPOINT|RUNTIME_HOST_AGENT_API_KEY|RUNTIME_API_KEY|HOST_AGENT_API_KEY|RIKUNE_API_KEY)=' <<<"$image_environment"; then
  echo "Hybrid image configuration must not bake runtime endpoints or credentials" >&2
  exit 1
fi

hardened_run=(
  --read-only
  --network none
  --security-opt no-new-privileges:true
  --cap-drop ALL
)

docker run --rm "${hardened_run[@]}" --entrypoint sh "$image_ref" -ceu '
  test ! -e /home/appuser
  test "$(getent passwd appuser | cut -d: -f6)" = /nonexistent
  for target in /app/dist /app/node_modules /app/packages /app/workers /app/src /app/scripts /app/package.json /app/LICENSE /app/DISCLOSURE /docker-entrypoint.sh; do
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
  test "$(stat -c %a /app/LICENSE)" = 444
  test "$(stat -c %a /app/DISCLOSURE)" = 444
  test "$(stat -c %a /app/scripts/secure-fs-helper.py)" = 555
  test "$(stat -c %a /app/scripts/verify-hybrid-runtime.mjs)" = 555
  test "$(stat -c %a /docker-entrypoint.sh)" = 555
  test -s /app/LICENSE
  test -s /app/DISCLOSURE
  grep -Fqi dual-use /app/DISCLOSURE
  test -s /app/dist/index.js
  test -s /app/package.json
  ! touch /app/dist/.hybrid-write-probe
  ! touch /app/node_modules/.hybrid-write-probe
  ! touch /app/src/.hybrid-write-probe
  ! touch /samples/.hybrid-write-probe
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

# Exercise the real entrypoint and default CMD with runtime delegation disabled.
# No HostAgent endpoint or credential is supplied to this smoke test.
docker run -d -i --name "$container_name" "${hardened_run[@]}" \
  -e RIKUNE_DOCKER_PROFILE=hybrid \
  -e NODE_ROLE=analyzer \
  -e RUNTIME_MODE=disabled \
  "${runtime_mounts[@]}" \
  "$image_ref" >/dev/null

started=false
for _attempt in $(seq 1 30); do
  if ! docker inspect "$container_name" --format '{{.State.Running}}' | grep -qx true; then
    break
  fi
  if docker logs "$container_name" 2>&1 | grep -Fq 'Starting Container Command'; then
    started=true
    break
  fi
  sleep 1
done

if [ "$started" != true ]; then
  docker logs "$container_name" >&2 || true
  echo "Hybrid read-only entrypoint did not reach the default command" >&2
  exit 1
fi

docker exec "$container_name" sh -ceu '
  command_line=$(tr "\000" " " < /proc/1/cmdline)
  case "$command_line" in
    *"node dist/index.js"*) ;;
    *) echo "unexpected PID 1 command: $command_line" >&2; exit 1 ;;
  esac
  test "$(id -u)" = 1000
  test "$(id -g)" = 1000
  test "$RIKUNE_DOCKER_PROFILE" = hybrid
  test "$NODE_ROLE" = analyzer
  test "$RUNTIME_MODE" = disabled
  test -z "${RUNTIME_HOST_AGENT_ENDPOINT:-}"
  test -z "${RUNTIME_HOST_AGENT_API_KEY:-}"
  for target in /app/workspaces /app/data /app/cache /app/logs /app/storage /app/uploads /ghidra-projects /ghidra-logs /tmp; do
    probe="$target/.hybrid-runtime-write-probe"
    : > "$probe"
    rm -f "$probe"
  done
  ! touch /app/dist/.hybrid-runtime-write-probe
  ! touch /app/node_modules/.hybrid-runtime-write-probe
  ! touch /app/src/.hybrid-runtime-write-probe
  test -s /app/scripts/verify-hybrid-runtime.mjs
'

docker stop --time 35 "$container_name" >/dev/null
docker rm "$container_name" >/dev/null
