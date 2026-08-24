#!/usr/bin/env bash
set -euo pipefail

compose_files=(
  docker-compose.analyzer.yml
  docker-compose.hybrid.yml
  docker-compose.yml
)

rendered=$(mktemp)
cleanup() {
  rm -f "$rendered"
}
trap cleanup EXIT

for compose_file in "${compose_files[@]}"; do
  if RIKUNE_API_KEY='' docker compose -f "$compose_file" config >/dev/null 2>&1; then
    echo "$compose_file accepted a missing API key" >&2
    exit 1
  fi

  RIKUNE_API_KEY=rikune-compose-contract-key \
    docker compose -f "$compose_file" config --format json > "$rendered"
  node --input-type=module - "$rendered" "$compose_file" <<'NODE'
import fs from 'node:fs'

const renderedPath = process.argv[2]
const composeFile = process.argv[3]
const document = JSON.parse(fs.readFileSync(renderedPath, 'utf8'))
const services = Object.values(document.services ?? {})
if (services.length !== 1) {
  throw new Error(`${composeFile} must define exactly one release service`)
}

const service = services[0]
if (Number(service.pids_limit) !== 512 || Number(service.deploy?.resources?.limits?.pids) !== 512) {
  throw new Error(`${composeFile} must set matching pids_limit and deploy pids limits`)
}

const apiPort = (service.ports ?? []).find((port) => Number(port.target) === 18080)
if (!apiPort || apiPort.host_ip !== '127.0.0.1' || Number(apiPort.published) !== 18080) {
  throw new Error(`${composeFile} must bind API port 18080 only on 127.0.0.1`)
}
NODE
done

RIKUNE_API_KEY=rikune-compose-contract-key \
  docker compose -f docker-compose.yml -f docker-compose.dev.yml config --format json > "$rendered"
node --input-type=module - "$rendered" <<'NODE'
import fs from 'node:fs'

const document = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
const service = document.services?.['mcp-server']
if (!service) throw new Error('merged full+dev Compose config is missing mcp-server')
const apiPorts = (service.ports ?? []).filter((port) => Number(port.target) === 18080)
if (
  apiPorts.length !== 1 ||
  apiPorts[0].host_ip !== '127.0.0.1' ||
  Number(apiPorts[0].published) !== 18080
) {
  throw new Error('merged full+dev Compose config must inherit exactly one loopback API port')
}
NODE
