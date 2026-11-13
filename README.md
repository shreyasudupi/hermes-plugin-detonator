# Plugin Detonator

![Plugin Detonator: a security testing sandbox for Hermes Agent plugins](docs/store/cover.png)

**Hermes Security reviews code you wrote. Detonator tests code you didn't.**

**Current version: v0.2.3** ([what's new](#versions))

[![Watch the 82-second Plugin Detonator demo](docs/demo-thumbnail.png)](https://x.com/shreyasudupi/status/2120289870908465286)

▶️ **[Watch the 82-second demo](https://x.com/shreyasudupi/status/2120289870908465286)**: a real run catching a fake key-stealer plugin, comparing two versions, the clock jump, and the plain-words AI explanation.

Detonator is a security sandbox for [Hermes Agent](https://hermes-agent.nousresearch.com/)
plugins. You point it at a plugin at an exact commit and approve the run. It then
loads that plugin inside a disposable Docker container with a fake Hermes home full
of decoys, fires synthetic hooks and tool calls at it, and reports what the plugin
actually did compared with what it declares. Each finding says, in plain words, why it
matters and which MITRE ATT&CK / ATLAS technique it matches.

Tested on Linux (x86_64), macOS on Apple Silicon (Docker Desktop) and Windows (Docker
Desktop with WSL 2, in both the `hermes` terminal chat and the Desktop app). Every change runs
the full test suite and Hermes's own `hermes plugins validate` in CI, including on Windows.
In the Desktop app, the very first `/detonate` can show "request timed out after 30s" while
the sandbox image builds (Desktop gives a slash command 30 seconds). Run the same command
again: the image is built by then, and runs take seconds. Or run the first one in the
`hermes` terminal chat, which has no limit.

## Try it in 60 seconds

You need [Docker](https://docs.docker.com/get-docker/) running and Hermes installed.
Not sure Docker is ready? Type `/detonate check` in Hermes: it only asks Docker for its
status, runs nothing, and tells you what to fix (see [Docker problems](#docker-problems)).

One command installs it, switches it on and restarts Hermes's plugin host so it loads:

```bash
hermes plugins install shreyasudupi/hermes-plugin-detonator && hermes plugins enable detonator && hermes gateway stop
hermes
```

On Windows PowerShell 5, use `;` instead of `&&`. New to Hermes or Docker? The
[step-by-step quickstart](docs/QUICKSTART.md) starts from nothing, on macOS, Windows and Linux.

In the Hermes chat:

```
/detonate <owner/repo> <40-char-sha> [subdir]
```

Detonator asks before it does anything. Pick **Run in sandbox**. The first run builds the
sandbox image (a minute or two); after that a run takes seconds:

```
🔴 DANGEROUS: the plugin did something stealers and malware do (took or leaked decoy secrets, ...).
- [critical] Read Hermes's .env file, where your API keys are kept, and also reached for the network or other secrets (T1552.001, AML.T0055)
  Why: It read your API keys and, in the same run, reached for the network or took other secrets. ...
- [high] Reached for the network while loading or from a background hook (the sandbox has no network; nothing left the box) (T1071.001, T1041, AML.T0025)
Full report: ~/.hermes/plugin-data/detonator/reports/....md
```

## Using it in Hermes

```
/detonate <owner/repo> <40-char-sha> [subdir]
```

or from a terminal: `hermes detonate <owner/repo> <40-char-sha> [--subdir path] [--compare-to new-sha]`.
`/detonate check` only tells you whether Docker is ready; it runs nothing.

Detonator always asks you before it runs anything. If no one can answer (a cron
job, a hook, a non-interactive or unattended run), it refuses instead of running.
There is no flag that skips the question. The `detonate_plugin` tool lets the
agent suggest a run, but it only returns the `/detonate` command for you to run.
Reports are saved under `<HERMES_HOME>/plugin-data/detonator/reports/`.

### Docker problems

`/detonate check` tells you which of these you have. Detonator shows the same advice
if a run fails for one of these reasons.

| What you see | What to do |
|---|---|
| Docker isn't installed, or can't be found | Install [Docker Desktop](https://docs.docker.com/get-docker/) (Mac, Windows), or Docker Engine on Linux. Colima, OrbStack and Rancher Desktop also work. |
| Docker is installed but not running | Open Docker Desktop (or start Colima or OrbStack) and wait until it says it is running. On Linux: `systemctl start docker`. |
| Your user isn't allowed to use Docker (Linux) | Add yourself to the `docker` group and log out and back in, or use rootless Docker. Members of that group control Docker, so do this only on your own machine. |
| Couldn't download the base image | The first run downloads `python:3.11-slim` once to build the sandbox. Check your internet, VPN or proxy. Later runs need no network. |
| Docker Hub download limit | Run `docker login` with a free Docker account, or wait a few hours. |
| Docker Desktop says "WSL not installed" (Windows) | Docker Desktop runs Linux containers through WSL 2. Open PowerShell as administrator, run `wsl --install`, restart the PC, then open Docker Desktop again. |
| Docker Desktop is set to Windows containers (Windows) | Right-click the Docker icon in the taskbar and choose **Switch to Linux containers...**. The sandbox is a Linux container. |
| Out of disk space | `docker system prune` removes stopped containers and unused images, or give Docker more disk in Docker Desktop (Settings > Resources). |
| Mounts denied | Docker Desktop: Settings > Resources > File sharing, add your temporary folder (on a Mac, `/var/folders`). Colima: start it with that folder mounted. |
| Docker didn't answer in time | Docker may still be starting. Wait a moment and try again. |

### Rules decide, AI explains

After a run, ask Hermes: "Use the detonator_report tool to explain my latest
Detonator report". (Naming the tool helps smaller models find it.) The read-only
`detonator_report` tool hands the saved verdict and findings to your model so it
can explain them in plain words: what each finding means and whether it looks
normal for this kind of plugin. The model never decides or changes the verdict.
A plugin can carry text written to talk an AI reviewer into calling it safe, so
the verdict comes from fixed rules only, and everything the tested plugin
produced is passed to the model as untrusted data with hidden characters removed.

## Compare two versions (rug-pull check)

A plugin can be clean when you install it and turn bad in an update. Give two commits
and Detonator runs both, then shows what the newer one does that the older one did not:

```
/detonate <owner/repo> <old-sha> <new-sha> [subdir]
```

```
⚠️ NEW VERSION IS RISKIER: it does things the old version did not.
Verdict: NO_FINDINGS (cc4d5721) → DANGEROUS (26e9a4b4)
New in this version:
+ [critical] Read Hermes's .env file, where your API keys are kept, and also reached for the network or other secrets (T1552.001, AML.T0055)
+ [high] Reached for the network while loading or from a background hook (...)
```

It also lists behaviour that went away and changes to what the plugin declares
(tools, hooks, env vars), and saves a diff report next to the two full reports. Useful
before `hermes plugins update`, or when reviewing a catalog SHA bump.

## What it checks

| Severity → verdict | Examples |
|---|---|
| critical → DANGEROUS | Reads decoy SSH or cloud keys, browser passwords or wallets; reads API keys and also reaches for the network; leaks a decoy secret; plants autostart, cron, LaunchAgent, `.bashrc` or `.pth` persistence |
| high → SUSPICIOUS | Reads Hermes's `.env` or API keys it does not declare; reads every key at once through `/proc`; did something only after the clock was moved forward (time bomb); network while loading or from a background hook; shell commands; downloads or installs code; rewrites itself; poisoned tool descriptions or prompt-injection text; shadows a built-in tool name; monkeypatches Python or Hermes; redirects proxies/PATH/API keys; tampers with monitoring; hidden hooks or tools; changes Hermes's config or files outside its folder; opens a listening port; a plugin name with `../` in it; floods the activity log to hide something |
| medium → REVIEW | Secret-file paths or start-up locations in code that never ran (possible time bomb); a declared prompt hook's added text; tools calling a host or localhost; reading memory or chat history; copying the whole environment; listing your home or key folders; reading system account files; calling other agent tools on its own; own state outside `plugin-data/`; exec of strings; sandbox checks; native code; crashing while loading |
| low / info | Shell, string-built code or network calls in code that never ran; coverage notes (stand-in modules), temp files, background threads, library behaviour |

**Every finding says why it matters and maps to [MITRE ATT&CK](https://attack.mitre.org/) and
[MITRE ATLAS](https://atlas.mitre.org/) techniques.** The full list, with each rule's reasoning and
technique IDs, is in [docs/RULES.md](docs/RULES.md). A test fails if a rule is added without
documenting it there.

Verdicts: `DANGEROUS`, `SUSPICIOUS`, `REVIEW`, `NO_FINDINGS`, `ERROR`. The verdict comes
from deterministic rules only. No model decides anything.

### Clock jump and code that stayed quiet

A short test only sees what a plugin does right away. Malware often waits: for a date,
or for days to pass after it was installed. So after the normal pass Detonator moves the
plugin's clock forward (30 days, 400 days, about 5 years) and fires its hooks and tools
again. `time.sleep` follows the moved clock, so a background thread that sleeps for hours
wakes up too. Anything that only happens after a jump is flagged as `time_triggered`
(high) and the finding says how many days it took.

Detonator also reads the source of every file the plugin loads (parsed with `ast` on
your machine, never executed) and compares it with what actually ran. Abilities that
exist in the code but stayed quiet are reported as `dormant_code`: secret-file paths or
start-up locations at **REVIEW**, with a note when the code also checks the date; shell,
string-built code and network calls as low/info notes, because honest tools often have
those on paths a synthetic test does not reach. Across the whole catalog, 37 of 1,043
plugins get a REVIEW verdict from this check alone (28 of them also check the date).

**The report is advisory evidence, not proof.** Sandbox-aware code, triggers other than
time (a keyword, a specific user) and code paths the synthetic inputs don't reach can still
evade it, and the Python audit hooks run in the same process as the plugin, so a determined
plugin could tamper with them or write a fake clean result. A clean report does not mean a
plugin is safe.

The sandbox image has no Hermes and no third-party packages. When a plugin imports one
(`tools.registry`, `httpx`, ...), Detonator gives it an inert stand-in so the rest of the
plugin still runs, and lists those modules in the report. Anything done *through* a
stand-in (for example an HTTP call made with `httpx`) is not observed. Standard-library
modules are never replaced. Portable `plugin.json` packages and desktop-only plugins have
no Python code to run, and Detonator says so instead of guessing.

## How it was tested

- **Every change** runs over 100 tests in CI, including real Docker sandbox runs, plus Hermes's own
  `hermes plugins validate` (the same check the catalog runs).
- **Detection** is checked against 23 harmless test plugins (fake keys, reserved TEST-NET
  addresses, `true` as the only command): stealers of keys, browser logins and memory, persistence,
  prompt injection, tool poisoning, a rug pull, a backdoor port, a config hijack, a log flood, a
  trojan update, a date-triggered time bomb, a sleeper thread, plus honest and grey-area plugins
  that must not be flagged as dangerous. All 23 get their expected verdict, together they set off
  every one of the 45 rules, and CI re-checks them on every change. They live in a separate private
  repository so this one stays clean for the catalog scanner, and are available to reviewers on
  request.
- **The whole catalog**: Detonator ran all 1,043 Python plugins in the Hermes plugin catalog at
  their pinned commits: 859 no findings, 137 review, 44 suspicious, 1 dangerous, 2 errors. The
  first pass had 7 dangerous results; each was checked by hand, all were false alarms, and the
  rules were tuned. Only totals are published, never plugin names. "Suspicious" usually means risky but
  undisclosed behaviour, not malware: the most common reasons were running shell commands (23),
  writing outside the plugin's folder (8) and reading undeclared API keys (7). The one dangerous
  result reads Hermes's .env for its own OpenRouter key and sends it to OpenRouter, which breaks
  catalog rule 11 but looks like a convenience fallback, not theft. The 2 errors are plugins that
  ran past the time limit or were stopped by the container.

## Disclosures (catalog rule 13)

Detonator does things a reviewer should know about:

- **Requires Docker.** It runs `docker build` once to build the sandbox image from
  `sandbox/Dockerfile` (a digest-pinned `python:3.11-slim` with nothing extra
  installed; this pulls the base image over the network), and `docker run` for each test.
- **Clones code.** For a GitHub target it runs `git init` / `git fetch` / `git checkout`
  of the exact 40-character SHA you give it, with git hooks disabled, no submodules, and symlinks checked out as plain files
  (links are never copied into the sandbox, so a repo cannot pull in real files from your machine).
  No code from the target runs on your machine outside the container.
- **Shell commands.** Only `git` and `docker`, as above, and only after you approve
  the run. No background processes.
- **Network.** Only for `git fetch` and the one-time image build. The sandbox
  container runs with `--network none`.
- **Credentials.** Detonator never reads your real Hermes home, `.env`, `auth.json`
  or any credential store. The sandbox gets its own fake home with fake keys.
  The `git` and `docker` commands it runs get only an allow-listed environment (PATH, HOME,
  locale, Docker and proxy settings), never the API keys Hermes has loaded.
- **Sandbox settings.** `--network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --user 10001:10001 --pids-limit 128 --memory 512m --cpus 1`,
  a 64 MB `/tmp`, a 180-second timeout, and an activity log capped at 5,000 events (a flood is
  reported, and the most repeated actions are thinned first so rare ones such as a key read are kept).
- **A different world every run.** Each run gets a random username, home folder
  (`/home/<name>`) and host name, and random fake-key values, so a plugin cannot spot
  the sandbox by a fixed path or a fixed marker in the decoys. The container's user
  and group lists are written per run (mounted read-only) so they name the same
  random user; the image itself has no sandbox account.

## Developer usage

```bash
pip install -r requirements-dev.txt      # pytest + PyYAML
python -m pytest -q                      # unit + Docker integration tests
python -m engine path/to/plugin          # detonate a local plugin directory
python -m engine --repo owner/name --sha <40-char sha> [--subdir path]
```

Only run untrusted plugins inside a disposable environment such as a Codespace or CI.
Harmless "malicious" test plugins are kept in a separate private repository, so this
repository stays clean for the catalog scanner. CI runs every one of them on each change.

## Versions

The version in `plugin.yaml` is the one listed here first; a test fails if they differ.

- **v0.2.3** (Nov 11, 2026): Windows fixes, found by the new Windows CI job. Reports and
  plugin files are always read and written as UTF-8 (Windows' default code page crashed on the
  report's symbols), and the rules always treat sandbox paths as Linux paths (on Windows some
  matches were missed, so a few verdicts came out different). `/detonate check` spots Docker
  Desktop set to Windows containers and says how to switch. `git` and `docker` keep the Windows settings they
  need (still no API keys), Docker Desktop's Windows folder is searched, Docker mount paths
  are clean on Windows, and files always check out with Linux line endings. Clear message when
  Docker Desktop isn't running on Windows. Tested on a real Windows PC: clean plugin
  NO_FINDINGS, key stealer and persistence planter DANGEROUS. CI now runs the
  tests and a Windows smoke test on a Windows machine.
- **v0.2.2** (Nov 11, 2026): Three new rules: reading every API key at once through `/proc`,
  a plugin name with `../` in it, and flooding the activity log to hide something. Report titles
  can't carry text from the plugin, and each run writes its own account files. Plain-language
  Docker errors and `/detonate check`. 23 test plugins now set off all 45 rules in CI, and
  GitHub Actions are pinned to exact commits.
  From the catalog review: `git` and `docker` now get a minimal, allow-listed environment, so
  Hermes's API keys never reach them, and `plugin.yaml` is read with Hermes's own YAML loader.
- **v0.2.1** (Nov 10, 2026): First public release, the version submitted to the Hermes plugin
  catalog. CI runs the fake-malicious test plugins on every change.
- **v0.2.0** (Nov 10, 2026): Clock jump (time bombs and sleepers), the dormant-code check, rules
  tuned on the whole catalog, read-only AI explanations (`detonator_report`), a random sandbox
  world every run, and the symlink fix.
- **v0.1** (Nov 9, 2026): First working version: the Docker sandbox with decoys, rules mapped to
  MITRE ATT&CK and ATLAS, `/detonate`, and comparing two versions.

## Layout

- `plugin.yaml`, `__init__.py`, `schemas.py`, `tools.py`, `commands.py`: the Hermes
  plugin (tool, `/detonate` slash command, `hermes detonate` CLI)
- `engine/`: host side (fetch, run Docker, rules, report)
- `sandbox/`: the container image and the in-container harness
- `tests/`: rule tests, plus integration tests that run harmless plugins in real Docker
- `ci/check_fixtures.py`: runs the private test plugins in CI and checks every rule fires
- `ci/windows_smoke.py`: Windows host checks in CI (git fetch, Docker message, mount paths)
- `docs/RULES.md`: every rule, why it matters, and its ATT&CK / ATLAS IDs
- `docs/QUICKSTART.md`: step-by-step install and first run; `CONTRIBUTING.md`: how to help

## Contributing

False alarms, missed behaviour and test reports from your machine (Windows and macOS especially)
all help. [CONTRIBUTING.md](CONTRIBUTING.md) covers the 5-minute setup, how detection is tested,
how to write a harmless test plugin, and how to add a rule. Sandbox escapes go privately through
[SECURITY.md](SECURITY.md).

## License

MIT
