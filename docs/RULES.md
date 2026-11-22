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
| `own_tool_config_read` | medium (high when the run also used the network; critical as `decoy_accessed` when anything else in the run is high-risk) | It is named for a tool (Kubernetes, Docker, AWS, GitHub, git, npm or PyPI) and opened only that tool's own login file, which it needs to do its job. With your real file, the real key would be in its reach, so install it only if you mean to give it that access. Any other key file, a key sent out or shown to the model, or anything else high-risk in the same run is reported as key theft instead. If it also used the network, the finding is high: a key could leave in a form the test cannot read. | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
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

`own_tool_config_read` replaces `decoy_accessed` only in a narrow case. The name the person chose to
install (the plugin's name, or the MCP server's config entry, package or folder name, never the name the
server reports about itself) must contain a whole word for the tool, and every key file read in the whole
run must be that tool's own login file: `~/.kube/config` (kubernetes, kubectl, k8s, kube, helm),
`~/.docker/config.json` (docker), `~/.aws/credentials` (aws), `~/.config/gh/hosts.yml` or
`~/.git-credentials` (github, gh), `~/.git-credentials` (git), `~/.npmrc` (npm) and `~/.pypirc` (pypi,
pip, twine). SSH keys, `~/.netrc`, Hermes's own files, browsers and wallets are never on that list. Reading
Hermes's `.env`, a browser or wallet file, Hermes's memory or chat history, or another process's environment
in the same run keeps every read as `decoy_accessed`. If the run reached the network at all (a connection or
a name lookup), the finding is high, so the verdict is SUSPICIOUS: a key that left encrypted would not be
recognised. At the very end, if anything else in the run is high or critical (the key sent out or
shown to the model, a time bomb, a risky install script, any other alarm), the finding is turned back into
`decoy_accessed`. Skills keep the usual rules.

Known limit: a tool named for Kubernetes that opens the Kubernetes login file and keeps the key for later,
without sending it or showing it during the test, looks the same as an honest one. That is why the finding
stays in the report as a REVIEW and is never dropped.

## Network

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `undeclared_network` | high | Nothing the user asked for needs the network while a plugin loads or inside a background hook. That is when beacons and stealers phone home. | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) [T1041](https://attack.mitre.org/techniques/T1041/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) |
| `collection_service` | high | Tunnels and request collectors (ngrok, Pipedream, webhook.site, interactsh and the like) give anyone a throwaway address that receives data. Honest servers talk to their own service; real malicious MCP packages sent their loot or relayed every tool call to these. Read from the names the fake internet answered. | [T1567](https://attack.mitre.org/techniques/T1567/) [T1572](https://attack.mitre.org/techniques/T1572/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) |
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
| `reverse_shell` | critical | A shell whose input and output go to a network connection hands the person's computer to whoever is listening (a reverse shell). Real malicious MCP servers on npm did this at install time and at start-up. No honest plugin or server needs one. Detonator looks for bash's `/dev/tcp`, an interactive `sh -i` whose own process connects out (a plain `bash -i` is what an honest terminal tool starts, so on its own it does not count), netcat or socat running a program, and Python's `pty.spawn`, in every program started and in npm install scripts (read from package.json, so it counts even when the sandbox's shell could not run it). | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) [T1071](https://attack.mitre.org/techniques/T1071/) [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050) |
| `remote_code_fetch` | high | Downloading or installing code at runtime means what you reviewed is not what runs. A plugin can turn malicious after it is approved (a rug pull). | [T1105](https://attack.mitre.org/techniques/T1105/) [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) |
| `obfuscated_code` | high | Code scrambled on purpose (javascript-obfuscator names like _0x1a2b, or a program decoded from a long list of numbers and run) hides what it does from people and from tests. Real npm malware hid its payload this way, often in a file the sandbox run never reached. Ordinary minified bundles do not count. MCP servers only: read from the server's own files and from packages with install scripts, never run. | [T1027](https://attack.mitre.org/techniques/T1027/) |
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
fake internet (every address and every port answers locally, every DNS lookup gets a made-up address, and whatever is
sent is logged). There is still no real network. The outside monitor runs by default; set
`DETONATOR_OUTSIDE=0` to switch it off, and the report then says it did not run.

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `secret_sent_out` | critical | A fake key actually reached the fake internet: the plugin sent it over the network (in a web request, a raw connection or a DNS lookup). With real keys, they would now be in someone else's hands. | [T1041](https://attack.mitre.org/techniques/T1041/) [T1048](https://attack.mitre.org/techniques/T1048/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `monitor_blind_spot` | critical (high when no file was involved) | The outside monitor, which the plugin cannot reach, saw the plugin's own process do this, but Detonator's monitor inside the plugin's process recorded nothing. Honest code does not slip past the inside monitor; code written to hide from it (or to switch it off) does. | [T1685](https://attack.mitre.org/techniques/T1685/) [T1106](https://attack.mitre.org/techniques/T1106/) |
| `result_forged` | critical | Something other than Detonator wrote, removed or linked the sandbox's result file. A plugin that writes its own result is trying to hand in a fake clean report; one that puts a link there is trying to make Detonator read some other file instead (Detonator never follows it). | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) [T1685](https://attack.mitre.org/techniques/T1685/) |

The outside monitor also adds evidence to two rules above: `decoy_accessed` when a program the plugin
started read a decoy file, and `monitor_tamper` when the plugin tried to trace or read another process,
or to signal one it may not touch. A refused signal 0, which only asks whether a process exists (as
pid-file and lock-file checks do), does not count.

## MCP servers

Rules for `/detonate-mcp`, which runs one MCP server (an entry from `mcp_servers:` in Hermes's
`config.yaml`) in the same sandbox with the outside monitor. A stand-in for Hermes lists the server's
tools, resources and prompts, calls every tool with test input (and a few more times), answers sampling
and form requests, and lists everything again. Then it starts the server once more with its clock 400
days ahead and repeats the run; anything new then is `time_triggered`, and tools that changed are
`mcp_rug_pull`. Tool names with letters from another alphabet are `lookalike_name`. Every `env` value
is replaced with a fake key. What the server does on the
computer is judged by the rules above that the outside monitor can see (key files, `.env`, network,
programs, writes, persistence, leaks); the rules below cover what only MCP servers can do, and the server's own entry in `config.yaml`.
A server process reading its own environment file (`/proc/self/environ`, or `/proc/<pid>/environ` with
its own or the server's process id) is not `environ_file_read`; any other process's environment is.

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `mcp_tool_poisoning` | critical (high when it asks for nothing secret and hides nothing) | MCP tool descriptions and parameter text go straight into the model's instructions. Text that tells the model to read secrets, call other tools or keep steps from the user turns every conversation that loads this server into an attack (tool poisoning). | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `mcp_cross_tool_instructions` | high | A tool's description gives orders about OTHER tools (Hermes's own terminal, messaging or file tools, or other servers). That lets one server change what trusted tools do, for example adding a hidden recipient to every message (tool shadowing). | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `mcp_rug_pull` | high (medium when it only said the tools changed) | The tools changed while the server was running. Hermes refreshes tools automatically when a server says they changed, so a server can pass review with clean descriptions and swap in different ones later. | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) |
| `mcp_readonly_lie` | critical | The tool says it is read-only (readOnlyHint), but it wrote files, ran a program or used the network when called. On servers marked `trust: untrusted`, Hermes skips the approval prompt for read-only tools, so this lie gets the action past the user. | [T1036](https://attack.mitre.org/techniques/T1036/) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `mcp_sampling_used` | high (critical with keys or hidden orders in the request) | The server asked Hermes to run the user's AI model on its own (MCP sampling, on by default in Hermes). That spends the user's key and lets the server put text in front of the model. | [T1496](https://attack.mitre.org/techniques/T1496/) [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034) |
| `mcp_credential_request` | high when it asks the user (medium for a tool parameter) | The server asks the user, or the model on the user's behalf, for a password, API key or private key. Honest servers get their keys from their `env` entry, set once by the user. | [T1056.002](https://attack.mitre.org/techniques/T1056/002/) [T1552](https://attack.mitre.org/techniques/T1552/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) |
| `mcp_extra_recipient` | high | A message the server sent for a tool went to an address the tool was not given, such as a hidden Bcc on every email. The person asked for one recipient; a copy goes to someone else. Detonator gives each tool its own test address and reads what leaves, including inside HTTPS. | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) [T1567](https://attack.mitre.org/techniques/T1567/) [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) |
| `mcp_install_script` | high when the scripts did something risky (info otherwise) | npm runs a package's install scripts the moment it is installed, before any tool is used and with all of the person's keys in reach. Detonator downloads with scripts switched off and runs them only in the sandbox; the finding says what they did there. | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [T1059.007](https://attack.mitre.org/techniques/T1059/007/) [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005) |
| `mcp_unpinned_launch` | medium | The config starts a package without an exact version, so Hermes runs whatever was published last. A clean test today says nothing about tomorrow's version, and a hijacked package reaches you on the next start. | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005) |
| `mcp_inline_secret` | medium | A key is written in plain text in config.yaml (or sent without encryption), where any plugin, backup or screen share can read it. Hermes can take it from its .env file instead. | – |
| `mcp_full_trust_third_party` | low | Hermes trusts MCP servers fully by default and runs their tools without asking. For code you did not write, `trust: untrusted` makes Hermes ask before each tool that is not read-only. | – |
| `server_not_started` | medium | The server did not start or did not answer, so little of it was observed. Servers that need a real account or extra packages stop early in the sandbox. | – |

## Skills

Used by `/detonate-skill`. The text rules read the skill's files on your computer without running anything; findings that honest skills also show (setting up cron, editing config, mentioning key files) stay at low unless the skill also shows a clear sign of attack. The rest come from running the skill's scripts and the commands its documents show, inside the sandbox. The usual rules for files, keys, persistence, reverse shells and leaks apply to those runs too.

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `skill_fetch_exec` | critical (command hidden in base64), high (raw address, paste, tunnel or free web host), medium (plain http), low (a named https site) | Downloading a script and running it straight away (curl ... | bash) runs whatever the server sends that day, with all of your keys in reach. Many honest tools install this way from their own site; fake "prerequisites" that hide the command in base64, or fetch it from a raw address or a paste site, are the most common real skill attack. | [T1105](https://attack.mitre.org/techniques/T1105/) [T1204.004](https://attack.mitre.org/techniques/T1204/004/) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `skill_installer_lure` | high (password archive, installer download, paste page), medium (tool from a free web host; removing the macOS download warning next to one) | The skill says you must first download and run a program, often from a password-protected archive (the password stops virus scanners from looking inside) or a free web host. Real malicious skills use this to install info-stealers; honest skills install tools from package managers. | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) [T1027.013](https://attack.mitre.org/techniques/T1027/013/) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) [AML.T0104](https://atlas.mitre.org/techniques/AML.T0104) |
| `skill_instruction_injection` | high (in the description), medium (in the body, only next to a clear sign of attack; low otherwise) | The skill's text tells the agent to ignore its other instructions, hide what it does from you or skip your approval. The agent reads every loaded skill as instructions, and the description is shown to the model on every turn. | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `skill_catch_all` | medium | A skill that asks to be used for every task gets loaded into far more conversations than it needs, which is how a poisoned skill reaches the most sessions. | [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) |
| `skill_hidden_text` | critical (invisible tag text with instructions), high | Invisible characters (Unicode tags, zero-width marks) or HTML comments carry text the model reads but a person looking at the skill does not see. Honest skills have no reason to hide instructions. | [T1027](https://attack.mitre.org/techniques/T1027/) [AML.T0068](https://atlas.mitre.org/techniques/AML.T0068) [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) |
| `skill_secret_request` | high (credential files asked for, or key files plus sending data out), medium/low | The skill points the agent at files that hold keys and passwords (SSH keys, cloud credentials, Hermes's .env or auth.json, wallets, browser logins), or asks Hermes to hand it credential files. Honest skills declare the one key they need and get it from Hermes. | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) |
| `skill_exfil_instruction` | medium (to a paste or tunnel site or raw address), low | The skill tells the agent to send files or data to an outside address. The agent would do it with its own tools, so nothing in the skill's code shows it. | [T1567](https://attack.mitre.org/techniques/T1567/) [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) |
| `skill_config_tamper` | medium (low on its own, or when it only runs another agent without its safety checks) | The skill tells the agent to change Hermes's own settings, memory, personality (SOUL.md) or safety switches. That can turn off approvals or plant instructions that outlive the skill. Setup skills do this honestly; a skill that has no reason to should not. | [T1685](https://attack.mitre.org/techniques/T1685/) [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) |
| `skill_persistence_instruction` | medium (low on its own) | The skill tells the agent to add something that starts on its own (a cron job, a login item, a line in your shell start-up file). Once added it keeps running after the chat is over. | [T1053](https://attack.mitre.org/techniques/T1053/) [T1546.004](https://attack.mitre.org/techniques/T1546/004/) |
| `skill_agent_tool_abuse` | medium (low on its own) | The skill tells the agent to use its other tools (messages, memory, scheduled jobs, writing new skills) for the skill's own purposes. A skill that writes more skills or schedules itself can spread and persist. | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) |
| `skill_reverse_shell_text` | high | The skill's files contain a reverse shell: a command that hands control of the computer to someone else over the network. | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `skill_destructive_text` | medium (low on its own) | The skill's files contain a command that wipes the home folder or a disk. | [T1485](https://attack.mitre.org/techniques/T1485/) [AML.T0101](https://atlas.mitre.org/techniques/AML.T0101) |
| `skill_inline_shell` | medium (risky command), low | Inline !`command` snippets run on your computer while Hermes loads the skill, before the model reads it and without asking. Hermes only runs them when skills.inline_shell is on (off by default, never for hub installs). | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `skill_blueprint_cron` | medium (risky job), low | The skill proposes a scheduled job. If you accept it, Hermes runs it again and again on its own. | [T1053](https://attack.mitre.org/techniques/T1053/) |
| `skill_config_phish` | medium | The skill asks for a password or key through a plain setting. Hermes stores those settings in config.yaml, not as secrets, and honest skills ask for keys through required_environment_variables. | [T1056.002](https://attack.mitre.org/techniques/T1056/002/) |
| `skill_shadowing` | low | The skill steps in when built-in tools are missing (fallback_for_*), so it decides what the agent uses in their place. | – |
| `skill_binary` | medium (low on its own) | Compiled programs and archives cannot be read like the rest of the skill, so they could hold anything. Honest skills rarely ship them. | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) |
| `skill_packed_script` | medium | The skill ships code that decodes and runs hidden code, or is packed into a few huge lines. Packing is the trick that let malicious skills slip past static scanners in published research. | [T1140](https://attack.mitre.org/techniques/T1140/) [T1027.013](https://attack.mitre.org/techniques/T1027/013/) |
| `skill_unlisted_script` | info | Scripts that SKILL.md never mentions. Common in honest skills (helpers); listed so you know what else ships. Detonator runs them anyway. | – |
| `skill_disguised_code` | medium (low on its own) | A file named like a document holds code. | [T1036.008](https://attack.mitre.org/techniques/T1036/008/) |
| `skill_symlink` | medium | Links inside a skill can point at files elsewhere on your computer. Detonator never follows them. | – |
| `skill_ran_downloaded_code` | critical (hidden, raw-address or throwaway host), high (plain http), low (an https site the skill names) | During the run a script was downloaded and executed. Detonator's fake internet answered with a harmless stand-in that only leaves a mark, and the mark showed up: on your computer, whatever the real server sends would have run. | [T1105](https://attack.mitre.org/techniques/T1105/) [T1059.004](https://attack.mitre.org/techniques/T1059/004/) [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) |
| `skill_undeclared_host` | medium (low when nothing connected) | The skill's scripts or commands contacted hosts that its own text never names. Honest skills talk to the services they describe; anything else may be where data goes. | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| `skill_declared_host` | info | Network use that matches the hosts the skill's own text names; listed for completeness. | – |
| `skill_not_fully_read` | medium | Files too big or too many to read in full. The agent still reads SKILL.md however long it is, and padding a file is a known way to hide instructions from scanners. Detonator reads the start and end of a huge SKILL.md and lists what it skipped. | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) |
| `skill_odd_encoding` | medium (SKILL.md), low (other files) | SKILL.md (or another text file) is not plain UTF-8: UTF-16, a one-byte encoding such as Latin-1, or stray NUL bytes. The agent may still read it, while tools that expect UTF-8 see nothing, so it is a way to hide instructions. Detonator decodes it and checks the text anyway. | [T1027](https://attack.mitre.org/techniques/T1027/) |
| `skill_left_running` | medium | A command or script left a program running after it ended, outside its own process group (a daemon). Detonator kills it before the next step; on a real computer it would keep running. | [T1543](https://attack.mitre.org/techniques/T1543/) |
| `skill_tool_own_config` | info / low | A package tool the skill tells the agent to run (npm, pip, git) used its own settings: npm reads ~/.npmrc and sends its registry token to its registry, pip and git look in ~/.netrc. That happens on every machine, so it is not counted as key theft. Only the real tool counts, and a token from that file sent anywhere but the tool's own registry is still reported as a leak. A tool changing its own settings, or an `export NAME=value` line added to a shell start-up file as the instructions say, is listed too, unless it changes where the tool connects. | – |

## Declarations and coverage

| Rule | Severity | Why it matters | MITRE |
|---|---|---|---|
| `undeclared_registration` | high | Registers hooks, tools or middleware missing from plugin.yaml, so users are not shown them at install time (catalog rule 6). | [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005) |
| `declared_not_registered` | low | Declares tools it did not register; usually a stale plugin.yaml. | – |
| `claim_mismatch` | high | The plugin describes itself one way (for example offline, read-only or never touching keys) but did the opposite in the sandbox. A description that hides what the code does is a warning sign on its own. | [T1036](https://attack.mitre.org/techniques/T1036/) |
| `load_error` | medium | The plugin crashed while loading, so less of it was observed. | – |
| `unsafe_plugin_name` | high | The plugin's name becomes the name of its own data folder, where it may write freely. A name with slashes or dot-dot steps could point that folder at your whole home folder, so harmful writes there would look allowed. Detonator used a safe folder instead. | [T1036](https://attack.mitre.org/techniques/T1036/) |
| `log_flood` | high | The plugin did so much that the sandbox's activity log filled up, so part of the run was not kept. Flooding a monitor is a known way to hide one bad action among thousands of harmless ones. Only the most repeated kinds of activity were thinned out, so rare actions such as a key read were kept and judged. | [T1685](https://attack.mitre.org/techniques/T1685/) |
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
| Python start-up hooks (`*.pth` in a `site-packages` or `dist-packages` folder, or anywhere when the run may have made a symbolic link; `sitecustomize.py`) | [T1546.018](https://attack.mitre.org/techniques/T1546/018/) |
| `crontab`, `systemctl`, `launchctl` commands | [T1053.003](https://attack.mitre.org/techniques/T1053/003/), [T1543](https://attack.mitre.org/techniques/T1543/) |

## What the sandbox plants

Fake, canary-marked copies (at the Linux paths inside the sandbox, whatever your own computer runs) of: `~/.hermes/.env`, `auth.json`, SSH key, AWS credentials, `.git-credentials`,
`.netrc`, Docker and Kubernetes config, `.npmrc`, `.pypirc`, GitHub CLI token, Chrome and Firefox saved
logins and cookies (Linux and macOS paths), Solana and Ethereum wallets, Bitcoin `wallet.dat` (Linux and
macOS paths), Electrum and Exodus wallets, Hermes memory files and an old
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
