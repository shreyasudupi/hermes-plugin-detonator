# Security policy

Detonator is a security tool, so bypasses matter. Thank you for reporting them.

## Reporting

- **A way for a plugin, MCP server or skill to escape the sandbox, reach your real files or keys, or reach the network:**
  please report it privately through GitHub's
  [private vulnerability reporting](https://github.com/shreyasudupi/hermes-plugin-detonator/security/advisories/new).
  Do not open a public issue for these.
- **A malicious behaviour Detonator misses, or a false alarm on a harmless plugin:** a normal
  [issue](https://github.com/shreyasudupi/hermes-plugin-detonator/issues) is fine. Please include
  a minimal, harmless example plugin, not real malware.

## Known limits

Reports are advisory evidence, not proof. The audit hooks run inside the same Python process as the
plugin, so a determined plugin could tamper with them or fake a clean result. Time bombs, sandbox
checks and code paths the synthetic inputs do not trigger can also evade a run. See the README for
the full list.

On Linux the sandbox containers share the host's kernel (Docker is not a virtual machine), so a
kernel bug could let tested code out; Docker Desktop on macOS and Windows adds a virtual machine.
Skills are tested the same way: their text is only read on your computer, and their commands run
only in the sandbox.

## Supported versions

Only the latest release gets fixes.
