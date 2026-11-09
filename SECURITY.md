# Security Policy

## Scope

`Zero-Trust-Agent-Firewall` checks actions proposed by AI agents—API requests, CLI commands, and UI interactions—against live system state and deterministic security rules before those actions execute.

### Security Controls
1. **No External Network Calls During Evaluation**: All state and rule checks run synchronously in memory (p99 0.109 ms in the recorded run against a 10 ms target; see `docs/images/firewall-benchmarks.jpg`), keeping session state, request parameters, and DOM trees inside your runtime boundary.
2. **Runtime Policy Updates & Redacted Audit Streaming**: Policies can be updated at runtime (`PUT /v1/policy`), and SHA-256 hash-linked audit entries stream asynchronously (`onAuditEntry`) with credential patterns masked (`[REDACTED]`).
3. **SSRF & Cloud Metadata Protection**: Blocks loopback (`127.0.0.0/8`, `::1`, `localhost`), private network ranges, IPv4-mapped IPv6 (`::ffff:127.0.0.1`), obfuscated integer/hex/octal IPs (`2130706433`, `0x7f.0.0.1`), and cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`).
4. **Command & Flag Injection Protection**: Enforces binary allowlists, blocks shell chaining (`;`, `|`, `&`, `` ` ``, `$()`), blocks code-evaluation and protocol-override flags (`--eval`, `-e`, `-c`, `--upload-pack`, `--checkpoint-action`), blocks dynamic linker overrides (`LD_PRELOAD`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`), and restricts execution to allowed working directories.
5. **Tamper-Evident Audit Chain**: Every `ALLOW`, `BLOCK`, and `HOLD` decision is linked into a SHA-256 hash chain starting from `GENESIS`.

## Reporting a Vulnerability

Please report suspected security issues via GitHub Security Advisories on [`abul-lab/Zero-Trust-Agent-Firewall`](https://github.com/abul-lab/Zero-Trust-Agent-Firewall/security/advisories). Do not open public issues containing live exploit payloads.
