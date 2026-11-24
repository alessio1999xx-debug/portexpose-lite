# portexpose-lite: find Docker Compose ports that publish past UFW

portexpose-lite reads one or more Docker Compose files and reports every published port: whether it binds to `0.0.0.0` / `::` (public), to loopback, or to a private/VPN address, and whether it is a sensitive service (PostgreSQL, MySQL/MariaDB, Redis, MongoDB, or the Docker API). It is read-only: it never changes Compose files, containers, or firewall rules. One file, Python 3.8+ standard library only, MIT.

Docker publishes ports through `nat`/`FORWARD` rules that sit in front of UFW's `INPUT` chain, so `ufw status` can say a port is denied while the container is still reachable. Official behaviour: [Docker packet filtering and firewalls](https://docs.docker.com/network/packet-filtering-firewalls/).

Need a live `docker inspect` of running containers, a check of the host `DOCKER-USER` iptables chain, or JSON output? That is the full [PortExpose](https://py-forge.com/products/portexpose-docker-firewall-auditor?utm_source=github&utm_medium=readme&utm_campaign=portexpose-lite) (one-time payment, yours to keep, no subscription). A table later in this README lists what lite does and what the paid tool adds. Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=portexpose-lite) ($99, one payment).

- Optional `pip install`, or just download the one file. No Docker socket, no iptables, no network access.
- Short and long Compose `ports:` syntax, port ranges, `host_ip`, IPv6, and a protocol suffix (`/tcp`, `/udp`).
- `expose:` is not a published port and is not reported.
- Exit code `1` when any binding is `HIGH` or `CRITICAL`, so it fits a CI job or a pre-check script. After `pip install`, use `portexpose-lite` in place of `python3 portexpose_lite.py`.

## Install

```bash
pip install portexpose-lite
portexpose-lite --help
```

Or download the single file (Python 3.8+, stdlib only, no extra packages):

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/portexpose-lite/main/portexpose_lite.py
python3 portexpose_lite.py --help
```

## See the output first (offline demo)

```bash
python3 portexpose_lite.py --demo
```

```
======================================================================
 portexpose-lite: Docker Compose published-port report
======================================================================
[CRITICAL] db       -> 0.0.0.0:5432  | Sensitive service (PostgreSQL) exposed publicly on wildcard 0.0.0.0:5432
[CRITICAL] redis    -> 0.0.0.0:6379  | Sensitive service (Redis) exposed publicly on wildcard 0.0.0.0:6379
[SAFE    ] web      -> 127.0.0.1:8080  | Bound strictly to loopback 127.0.0.1:8080
[HIGH    ] adminer  -> 0.0.0.0:8081  | Port 8081 exposed publicly on wildcard 0.0.0.0
======================================================================
Read-only: no files or firewall rules were changed.
```

The demo uses a built-in sample Compose file. Captured on 25 November 2026, Europe/Rome; real command and output.

## Audit your Compose file

```bash
python3 portexpose_lite.py                         # docker-compose.yml / compose.yaml in the current directory
python3 portexpose_lite.py -f docker-compose.yml
python3 portexpose_lite.py -f compose.yaml compose.override.yaml
```

## What gets flagged

| Level | Meaning |
| --- | --- |
| `CRITICAL` | A sensitive port is published on a wildcard (`0.0.0.0` / `::`) or a public address. Sensitive ports in lite: 5432 PostgreSQL, 3306 MySQL/MariaDB, 6379 Redis, 27017 MongoDB, 2375/2376 Docker API |
| `HIGH` | Some other port is published on a wildcard or a public address |
| `LOW` | The port is bound to a private or VPN address (for example `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) |
| `SAFE` | The port is bound only to loopback (`127.0.0.1` or `::1`) |

Omitted `host_ip` in Compose is treated as `0.0.0.0`, which is also Docker's default.

## Exit codes for CI

| Exit code | Meaning |
| --- | --- |
| `0` | No `HIGH` or `CRITICAL` findings (only `SAFE` / `LOW`, or no published ports) |
| `1` | At least one `HIGH` or `CRITICAL` binding |
| `2` | The file could not be read or parsed |

## portexpose-lite vs PortExpose

portexpose-lite reads Compose files and prints a plain-text report. That's it.

The full [PortExpose](https://py-forge.com/products/portexpose-docker-firewall-auditor?utm_source=github&utm_medium=readme&utm_campaign=portexpose-lite) also reads `docker inspect` JSON, checks the host `DOCKER-USER` iptables chain, and writes JSON. One-time payment, yours to keep. No subscription.

Lite is not a strict subset: it exits `1` when a public binding is found (the paid tool exits `0` with findings). Lite also treats only database, cache and Docker API ports as sensitive; the paid tool also labels some web-admin ports (for example 8080, 3000, 9000) as sensitive.

| Capability | Lite (free) | Paid PortExpose |
| --- | --- | --- |
| Read Compose files (short and long `ports:` syntax, ranges, several files) | Yes | Yes |
| Rate bindings: public wildcard, loopback, private/VPN | Yes | Yes |
| Flag PostgreSQL, Redis, MongoDB, Docker API (and, in lite, MySQL/MariaDB) | Yes | Yes |
| Live `docker inspect` JSON (`--inspect-json`) | No | Yes |
| Host `DOCKER-USER` iptables chain (`--check-iptables`) | No | Yes |
| JSON output (`--json`) | No | Yes |
| Exit code `1` when a public binding is found | Yes | No (exits `0`) |
| Offline `--demo` | Yes | Yes, plus a built-in `--self-test` |

Neither version changes firewall rules, Compose files, or running containers.

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=portexpose-lite) ($99, one payment).

## Limits

- This is a Compose-file reader, not a live firewall audit. It does not look at running containers or iptables.
- The YAML parser is a Compose-sized subset: mappings, lists, quoted/plain scalars, comments, and flow `[...]` / `{...}`. Anchors, merge keys and multiline `\|` / `>` scalars are not supported; the tool exits `2` if it cannot parse the file.
- IPv4 and IPv6 addresses are classified with the Python standard library (`ipaddress`). Unusual Docker host-network setups are outside the scope of lite.

## Tests

```bash
python3 test_portexpose_lite.py
```

The tests are offline. No Docker and no network needed.

## Other free tools from the same author

- [agentconfig-audit-lite](https://github.com/alessio1999xx-debug/agentconfig-audit-lite) — Audit MCP config for secrets: plaintext tokens and unpinned npx/uvx servers in `.mcp.json` and `CLAUDE.md`.
- [agenttrail-scrub-lite](https://github.com/alessio1999xx-debug/agenttrail-scrub-lite) — Claude Code secret scanner: find API keys and tokens leaked in AI agent transcripts.
- [cronpulse-lite](https://github.com/alessio1999xx-debug/cronpulse-lite) — Cron job monitoring in one Python file: alerts on failure or hang.
- [depcooldown-lite](https://github.com/alessio1999xx-debug/depcooldown-lite) — Dependency cooldown check: fail CI when a pinned PyPI or npm package is newer than N days.
- [homelab-doctor-lite](https://github.com/alessio1999xx-debug/homelab-doctor-lite) — Read-only homelab health check: stale images, exposed ports, expiring certs, silent cron, disk.
- [imagenudge-lite](https://github.com/alessio1999xx-debug/imagenudge-lite) — Docker image update checker: find running containers with a newer image (digest or tag).
- [pthguard-lite](https://github.com/alessio1999xx-debug/pthguard-lite) — Scan Python site-packages for malicious `.pth` files and startup backdoors.
- [pulseping-lite](https://github.com/alessio1999xx-debug/pulseping-lite) — Check SSL certificate expiry and URL/port uptime from cron.
- [sbom-snapshot-lite](https://github.com/alessio1999xx-debug/sbom-snapshot-lite) — Snapshot installed Python packages to a CycloneDX 1.5 SBOM, offline.
- [secenv-lite](https://github.com/alessio1999xx-debug/secenv-lite) — Find `.env` files committed to git or missing from `.gitignore`, plus obvious API keys inside.
- [ssh-keyaudit-lite](https://github.com/alessio1999xx-debug/ssh-keyaudit-lite) — Audit authorized_keys: SHA256 fingerprints; flags DSA, weak RSA, no comment and invalid lines.

## License

MIT (this lite version). The full PortExpose is sold separately under its own license.
