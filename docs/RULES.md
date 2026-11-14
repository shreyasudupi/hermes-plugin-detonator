# Detonator rules

Every finding in a report comes from one of these rules. Verdicts follow the worst severity:
**critical → DANGEROUS, high → SUSPICIOUS, medium → REVIEW**, low and info never change the verdict.

Technique IDs come from [MITRE ATT&CK Enterprise](https://attack.mitre.org/) (v20) and
[MITRE ATLAS](https://atlas.mitre.org/) (v5.6), the ATT&CK-style matrix for attacks on AI systems.
They say what the behaviour resembles, not what the author intended.

This page is checked by `tests/test_rules_doc.py`: adding a rule without documenting it fails the build.

## Credentials and private data

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `decoy_accessed` | critical | Plugins have no reason to open your key files or ask for API keys they did not declare. This is the first step of every credential stealer. | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) [T1552.004](https://attack.mitre.org/techniques/T1552/004/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) |
| `browser_or_wallet_read` | critical | Saved browser passwords, cookies and crypto wallets are what info-stealer malware is built to take. | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) [T1005](https://attack.mitre.org/techniques/T1005/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `secret_in_output` | critical | A fake key ended up somewhere it could leave the machine (a model prompt, a tool result, a network address, a command or another tool's input), even when encoded or split up to hide it. A real key would leak the same way. | [T1041](https://attack.mitre.org/techniques/T1041/) [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) |
| `memory_read` | medium | Memory and chat history hold what the agent knows about you. Expected for memory plugins, a privacy leak for anything else. | [T1005](https://attack.mitre.org/techniques/T1005/) |
| `env_enumerated` | medium (info when a library does it) | Copying the whole environment collects every API key at once. | [T1552](https://attack.mitre.org/techniques/T1552/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `environ_file_read` | high (medium when a library does it) | Read the process environment as a file under /proc instead of asking for variables by name. That gets every API key at once and skips the usual way of reading them, which is how stealers try to slip past simple monitors. | [T1552](https://attack.mitre.org/techniques/T1552/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `hermes_env_read` | high | Hermes keeps your API keys in the .env file in its home folder and already loads them for plugins. The catalog rules say plugins must never read that file; a plugin that opens it gets every key at once. Honest plugins sometimes do this to find their own key, so check which key it needs and whether it declares it. | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `undeclared_env_read` | high | Plugins must list every API key they use in requires_env. Reading one it never declared is often a fallback to a common key (such as OPENAI_API_KEY), but it is also how stealers collect keys quietly. | [T1552](https://attack.mitre.org/techniques/T1552/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `declared_env_read` | info | Reading a key the plugin says it needs is normal; listed for completeness. | – |
| `decoy_dir_listed` | medium | Listing your home folder or the folders that hold keys and memory is how stealers find what to take. | [T1083](https://attack.mitre.org/techniques/T1083/) [AML.T0084](https://atlas.mitre.org/techniques/AML.T0084) |
| `fs_discovery` | medium | Walking through many folders outside its own looks like searching for files to take. | [T1083](https://attack.mitre.org/techniques/T1083/) |
| `recon` | medium | Reading account and system files tells malware who you are and what machine it is on. | [T1082](https://attack.mitre.org/techniques/T1082/) [T1087](https://attack.mitre.org/techniques/T1087/) |

## Network

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `undeclared_network` | high | Nothing the user asked for needs the network while a plugin loads or inside a background hook. That is when beacons and stealers phone home. | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) [T1041](https://attack.mitre.org/techniques/T1041/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) |
| `tool_network` | medium | Expected for tools that wrap an API. Compare the hosts with what the README says the plugin connects to. | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| `local_network` | medium | Local services (databases, dev servers, the Hermes gateway) often trust anything on localhost without a password. | [T1046](https://attack.mitre.org/techniques/T1046/) |
| `listener` | high | Opening a port lets something outside talk to the plugin: a classic backdoor. | [T1571](https://attack.mitre.org/techniques/T1571/) |

## What the model sees

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `content_altered` | high (medium for a declared hook doing its job, low for a declared guard that only blocks calls or asks for approval) | Hermes uses what this hook returns. Text added to prompts, tool results or memory becomes instructions the model follows, which is the main route for prompt injection. | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0080](https://atlas.mitre.org/techniques/AML.T0080) |
| `prompt_injection_text` | high | Contains wording written to steer the model, such as telling it to disregard its earlier guidance or to keep a step secret from the user, or invisible characters. Poisoned tools hide orders to the model this way. | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `tool_shadowing` | high | Registers a tool with the same name as a built-in Hermes tool, so the model may call the plugin's version (and hand it data) when it meant the real one. | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `agent_tool_call` | medium | The plugin called other agent tools by itself, without the model or user asking. That can be used to send data out through tools the user trusts. | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) |
| `chat_data_sent` | high | Your messages, the model's replies and tool results are private. Sending them to the network or into a command from a background hook means a copy of your conversations leaves the machine. Logging and analytics plugins do this on purpose, so check where it goes and whether the plugin says so. | [T1041](https://attack.mitre.org/techniques/T1041/) [T1020](https://attack.mitre.org/techniques/T1020/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) |
| `tool_args_changed` | critical when calls are sent somewhere new, high from a hook or undeclared middleware, medium from declared middleware | Changed what a tool call does after the model chose it and before it ran (for example a different message recipient, web address or command). The user and the model see the call they asked for; the plugin quietly runs another one. | [T1565.002](https://attack.mitre.org/techniques/T1565/002/) [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `model_request_changed` | critical for a new server or credentials, high for model or messages (medium when the middleware is declared), low for other settings | Rewrote the request Hermes sends to the AI model. Changing the server or headers can send every prompt and your API key somewhere else; changing the model or the messages changes how the agent behaves without the user seeing it. | [T1557](https://attack.mitre.org/techniques/T1557/) [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `middleware_registered` | low | Hermes middleware can rewrite tool calls and model requests or wrap them entirely. That is a legitimate feature (declared in plugin.yaml as provides_middleware), and also the most direct way to tamper with what the agent does. Detonator drove it with test calls; read the findings around it. | – |
| `lookalike_name` | high (medium when one letter or only separators differ) | Registers a tool whose name looks like a built-in Hermes tool (a swapped letter, a digit for a letter, a letter from another alphabet). The model may pick it by mistake and hand it data meant for the real tool. | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `output_flood` | high from a hook or middleware, medium from a tool result | Puts a very large amount of text in front of the model. Every extra character costs the user money on every turn, can push the user's own instructions out of the model's memory, and gives room to hide orders deep inside. | [T1499](https://attack.mitre.org/techniques/T1499/) [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029) [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034) |

## Running code, persistence and writes

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `command_run` | high | Shell commands can do anything you can. Hermes plugins rarely need them, and catalog rule 13 requires disclosing them. | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| `remote_code_fetch` | high | Downloading or installing code at runtime means what you reviewed is not what runs. A plugin can turn malicious after it is approved (a rug pull). | [T1105](https://attack.mitre.org/techniques/T1105/) [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) |
| `self_modify` | high | Changing its own files at runtime is self-updating code (catalog rule 3): a reviewed plugin could rewrite itself later. | [T1554](https://attack.mitre.org/techniques/T1554/) [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) |
| `persistence` | critical | Writes to places that make code start automatically (login items, cron, systemd, shell start-up files, Python start-up hooks, SSH authorized keys). Malware does this to survive uninstalling. | – |
| `agent_config_modified` | high | Changes Hermes's own config, other plugins, skills or hooks. That changes how the agent behaves for every future session. | [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) |
| `write_outside_folder` | high | Wrote or changed sensitive files outside its folder (shell, SSH, cloud config or system paths). | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) |
| `write_own_state` | medium | Keeps files outside Hermes's plugin data folder. Usually harmless state, but it is not where Hermes expects plugins to write, so uninstalling may leave it behind. | – |
| `write_tmp` | low | Temporary files; listed for completeness. | – |
| `dynamic_code` | medium (info when a library does it) | Runs code it builds from a string at runtime (exec/eval). That is how obfuscated payloads are hidden from reviewers. | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) [T1027](https://attack.mitre.org/techniques/T1027/) [AML.T0068](https://atlas.mitre.org/techniques/AML.T0068) |
| `hidden_code` | high | Loads compiled bytecode or a pickle that reaches system functions. Both hide code that cannot be read in the source. | [T1620](https://attack.mitre.org/techniques/T1620/) [T1027](https://attack.mitre.org/techniques/T1027/) |
| `native_code` | medium | Loads native libraries via ctypes, which bypasses Python-level monitoring. | [T1106](https://attack.mitre.org/techniques/T1106/) |

## Tampering and evasion

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `monkeypatch` | high | Replaced functions inside Python or Hermes. That lets a plugin silently watch or change everything other code does (catalog rule 9: no core overrides). | [T1574](https://attack.mitre.org/techniques/T1574/) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `env_tampering` | high | Changed environment variables that redirect network traffic or which code gets loaded (proxies, PATH, LD_PRELOAD, PYTHONPATH, CA bundles). | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) [T1574.007](https://attack.mitre.org/techniques/T1574/007/) [T1090](https://attack.mitre.org/techniques/T1090/) |
| `sandbox_check` | medium | Checked whether it runs in a container or under a debugger. Malware does this to behave nicely while it is being tested. | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) |
| `monitor_tamper` | high | Tried to add its own audit hook or inspect the interpreter's live objects, which can be used to hide from or disable monitoring. | [T1685](https://attack.mitre.org/techniques/T1685/) |
| `background_thread` | info | Started background threads. Fine for batching or polling, but catalog rule 13 asks for background work to be disclosed. | – |
| `time_triggered` | high | Did something only after its clock was moved forward. Malware waits for a date, or for days to pass after install, so it passes short tests and reviews (a time bomb). | [T1480](https://attack.mitre.org/techniques/T1480/) [T1497.003](https://attack.mitre.org/techniques/T1497/003/) |
| `dormant_code` | medium | The code can do this, but it never did during the test. Code that stays quiet in a sandbox may be waiting for a date, a keyword or a real key (a time bomb or trigger). Often it is just a path the test did not reach, so read that code before installing. | [T1480](https://attack.mitre.org/techniques/T1480/) [T1497.003](https://attack.mitre.org/techniques/T1497/003/) |

## Outside monitor

These come from two containers that run next to the plugin's and that it cannot reach: a tracer
(strace, attached before the plugin loads, following every thread and every program it starts) and a
fake internet (every address answers locally, every DNS lookup gets a made-up address, and whatever is
sent is logged). There is still no real network. The outside monitor runs by default; set
`DETONATOR_OUTSIDE=0` to switch it off, and the report then says it did not run.

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `secret_sent_out` | critical | A fake key actually reached the fake internet: the plugin sent it over the network (in a web request, a raw connection or a DNS lookup). With real keys, they would now be in someone else's hands. | [T1041](https://attack.mitre.org/techniques/T1041/) [T1048](https://attack.mitre.org/techniques/T1048/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `monitor_blind_spot` | critical (high when no file was involved) | The outside monitor, which the plugin cannot reach, saw the plugin's own process do this, but Detonator's monitor inside the plugin's process recorded nothing. Honest code does not slip past the inside monitor; code written to hide from it (or to switch it off) does. | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) [T1106](https://attack.mitre.org/techniques/T1106/) |
| `result_forged` | critical | Something other than Detonator wrote the sandbox's result file. A plugin that writes its own result is trying to hand in a fake clean report. | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |

The outside monitor also adds evidence to two rules above: `decoy_accessed` when a program the plugin
started read a decoy file, and `monitor_tamper` when the plugin tried to trace or read another process.

## Declarations and coverage

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `undeclared_registration` | high | Registers hooks, tools or middleware missing from plugin.yaml, so users are not shown them at install time (catalog rule 6). | [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005) |
| `declared_not_registered` | low | Declares tools it did not register; usually a stale plugin.yaml. | – |
| `claim_mismatch` | high | The plugin describes itself one way (for example offline, read-only or never touching keys) but did the opposite in the sandbox. A description that hides what the code does is a warning sign on its own. | [T1036](https://attack.mitre.org/techniques/T1036/) |
| `load_error` | medium | The plugin crashed while loading, so less of it was observed. | – |
| `unsafe_plugin_name` | high | The plugin's name becomes the name of its own data folder, where it may write freely. A name with slashes or dot-dot steps could point that folder at your whole home folder, so harmful writes there would look allowed. Detonator used a safe folder instead. | [T1036](https://attack.mitre.org/techniques/T1036/) |
| `log_flood` | high | The plugin did so much that the sandbox's activity log filled up, so part of the run was not kept. Flooding a monitor is a known way to hide one bad action among thousands of harmless ones. Only the most repeated kinds of activity were thinned out, so rare actions such as a key read were kept and judged. | [T1562](https://attack.mitre.org/techniques/T1562/) |
| `coverage_incomplete` | low (medium when slow code used up the run's time) | The plugin stopped on a stand-in module, so code after that point was not observed. | – |
| `coverage_stubbed_imports` | info | The sandbox has no Hermes or third-party packages. Imports were replaced by inert stand-ins, and anything done through them (e.g. an HTTP call via httpx) was not observed. | – |

## Persistence locations

`persistence` adds the exact ATT&CK sub-technique for what was touched:

| Location | ATT&CK |
|---|---|
| `Library/LaunchAgents/` | [T1543.001](https://attack.mitre.org/techniques/T1543/001/) |
| `Library/LaunchDaemons/` | [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| `.config/autostart/` | [T1547.013](https://attack.mitre.org/techniques/T1547/013/) |
| `.config/systemd/user/` | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) |
| `/etc/systemd/` | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) |
| `/var/spool/cron` | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| `/etc/cron` | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| `.ssh/authorized_keys` | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) |
| shell start-up files (`.bashrc`, `.zshrc`, `.profile`, ...) | [T1546.004](https://attack.mitre.org/techniques/T1546/004/) |
| Python start-up hooks (`*.pth`, `sitecustomize.py`) | [T1546.018](https://attack.mitre.org/techniques/T1546/018/) |
| `crontab`, `systemctl`, `launchctl` commands | [T1053.003](https://attack.mitre.org/techniques/T1053/003/), [T1543](https://attack.mitre.org/techniques/T1543/) |

## What the sandbox plants

Fake, canary-marked copies of: `~/.hermes/.env`, `auth.json`, SSH key, AWS credentials, `.git-credentials`,
`.netrc`, Docker and Kubernetes config, `.npmrc`, `.pypirc`, GitHub CLI token, Chrome and Firefox saved
logins and cookies (Linux and macOS paths), Solana and Ethereum wallets, Hermes memory files and an old
chat transcript, plus five API-key environment variables. Any of these markers showing up in a tool
result, hook or middleware output, network address, command line or another tool's input is a
`secret_in_output` finding; one that reaches the fake internet is a
`secret_sent_out` finding. Both checks also undo common disguises before searching: base64 and base32,
hex, URL escapes, rot13, reversed text, zlib/gzip compression, layers of these, and keys split into pieces
(across DNS labels or several requests). Encryption with a key only the plugin knows is not undone; the report
still lists every address the plugin sent data to.

One exception, because it is what honest API plugins do: a tool call that sends the plugin's own
declared key (listed in `requires_env`) as-is to one host, for example in an `Authorization` header,
is reported under `tool_network` (REVIEW) with the key name and host, so you can check the host
belongs to that service. The same key disguised, sent to a second host, sent while loading or from a
hook, or sent along with any other key is still a leak.

The fake user message, model reply, system prompt and tool results that Detonator sends to hooks carry
their own canaries. Those turning up in a network call or command is a `chat_data_sent` finding.

`pre_tool_call` hooks and tool middleware are called with four kinds of tool call (a shell command, a
message, a web page fetch and a file write), so a plugin that only rewrites some of them is still seen.

## Sources

- MITRE ATLAS data v5.6: https://github.com/mitre-atlas/atlas-data
- MITRE ATT&CK Enterprise v20: https://github.com/mitre-attack/attack-stix-data
- MCP tool poisoning, shadowing and rug pulls: https://www.softwareseni.com/tool-poisoning-tool-shadowing-and-rugpull-attacks-the-ai
- Malicious PyPI packages (persistence, download-and-execute): https://www.zscaler.com/blogs/security-research/malicious-pypi-packages-deliver-silentsync-rat
- PyPI/npm stealers (browser data, wallets, staged downloads): https://thehackernews.com/2025/08/malicious-pypi-and-npm-packages.html
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/
