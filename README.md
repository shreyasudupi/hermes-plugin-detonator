# Plugin Detonator

**Hermes Security reviews code you wrote. Detonator tests code you didn't.**

Detonator is a dynamic sandbox for [Hermes Agent](https://hermes-agent.nousresearch.com/)
plugins. You point it at a plugin at an exact commit and approve the run. It then
loads that plugin inside a disposable Docker container with a fake Hermes home full
of decoys, fires synthetic hooks and tool calls at it, and reports what the plugin
actually did compared with what it declares.

> Status: hackathon build in progress.

## Using it in Hermes

```
hermes plugins install shreyasudupi/hermes-plugin-detonator
hermes plugins enable detonator
```

Then, in a Hermes session:

```
/detonate <owner/repo> <40-char-sha> [subdir]
```

or from a terminal: `hermes detonate <owner/repo> <40-char-sha> [--subdir path] [--compare-to new-sha]`.

Detonator always asks you before it runs anything. If no one can answer (a cron
job, a hook, a non-interactive or unattended run), it refuses instead of running.
There is no flag that skips the question. The `detonate_plugin` tool lets the
agent suggest a run, but it only returns the `/detonate` command for you to run.
Reports are saved under `<HERMES_HOME>/plugin-data/detonator/reports/`.

## Compare two versions (rug-pull check)

A plugin can be clean when you install it and turn bad in an update. Give two commits
and Detonator runs both, then shows what the newer one does that the older one did not:

```
/detonate <owner/repo> <old-sha> <new-sha> [subdir]
```

```
⚠️ NEW VERSION IS RISKIER: it does things the old version did not.
Verdict: NO_FINDINGS (eea9e9b8) → DANGEROUS (dafae722)
New in this version:
+ [critical] Read decoy secret files (keys, tokens, .env) (T1552.001, T1552.004, AML.T0055, AML.T0083)
+ [high] Reached for the network while loading or from a background hook (...)
```

It also lists behaviour that went away and changes to what the plugin declares
(tools, hooks, env vars), and saves a diff report next to the two full reports. Useful
before `hermes plugins update`, or when reviewing a catalog SHA bump.

## What it checks

| Severity → verdict | Examples |
|---|---|
| critical → DANGEROUS | Reads decoy keys, `.env`, browser passwords or wallets; leaks a decoy secret; plants autostart, cron, LaunchAgent, `.bashrc` or `.pth` persistence |
| high → SUSPICIOUS | Network while loading or from a background hook; shell commands; downloads or installs code; rewrites itself; poisoned tool descriptions or prompt-injection text; shadows a built-in tool name; monkeypatches Python or Hermes; redirects proxies/PATH/API keys; tampers with monitoring; hidden hooks or tools |
| medium → REVIEW | A declared prompt hook's added text; tools calling a host or localhost; reading memory or chat history; own state outside `plugin-data/`; exec of strings; sandbox checks; native code |
| low / info | Coverage notes (stand-in modules), temp files, background threads, library behaviour |

**Every finding says why it matters and maps to [MITRE ATT&CK](https://attack.mitre.org/) and
[MITRE ATLAS](https://atlas.mitre.org/) techniques.** The full list, with each rule's reasoning and
technique IDs, is in [docs/RULES.md](docs/RULES.md). A test fails if a rule is added without
documenting it there.

Verdicts: `DANGEROUS`, `SUSPICIOUS`, `REVIEW`, `NO_FINDINGS`, `ERROR`. The verdict comes
from deterministic rules only. No model decides anything.

**The report is advisory evidence, not proof.** Time bombs, sandbox-aware code and
code paths the synthetic inputs don't reach can evade it, and the Python audit hooks
run in the same process as the plugin. A clean report does not mean a plugin is safe.

The sandbox image has no Hermes and no third-party packages. When a plugin imports one
(`tools.registry`, `httpx`, ...), Detonator gives it an inert stand-in so the rest of the
plugin still runs, and lists those modules in the report. Anything done *through* a
stand-in (for example an HTTP call made with `httpx`) is not observed. Standard-library
modules are never replaced. Portable `plugin.json` packages and desktop-only plugins have
no Python code to run, and Detonator says so instead of guessing.

## Disclosures (catalog rule 13)

Detonator does things a reviewer should know about:

- **Requires Docker.** It runs `docker build` once to build the sandbox image from
  `sandbox/Dockerfile` (a digest-pinned `python:3.11-slim` with nothing extra
  installed; this pulls the base image over the network), and `docker run` for each test.
- **Clones code.** For a GitHub target it runs `git init` / `git fetch` / `git checkout`
  of the exact 40-character SHA you give it, with git hooks disabled and no submodules.
  No code from the target runs on your machine outside the container.
- **Shell commands.** Only `git` and `docker`, as above, and only after you approve
  the run. No background processes.
- **Network.** Only for `git fetch` and the one-time image build. The sandbox
  container runs with `--network none`.
- **Credentials.** Detonator never reads your real Hermes home, `.env`, `auth.json`
  or any credential store. The sandbox gets its own fake home with fake keys.
- **Sandbox settings.** `--network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --user 10001:10001 --pids-limit 128 --memory 512m`,
  a 64 MB `/tmp`, and a 180-second timeout.

## Developer usage

```bash
pip install -r requirements-dev.txt      # pytest + PyYAML
python -m pytest -q                      # unit + Docker integration tests
python -m engine path/to/plugin          # detonate a local plugin directory
python -m engine --repo owner/name --sha <40-char sha> [--subdir path]
```

Only run untrusted plugins inside a disposable environment such as a Codespace or CI.
Harmless "malicious" test fixtures live in a separate repository,
`detonator-test-fixtures`, so this repository stays clean for the catalog scanner.

## Layout

- `plugin.yaml`, `__init__.py`, `schemas.py`, `tools.py`, `commands.py`: the Hermes
  plugin (tool, `/detonate` slash command, `hermes detonate` CLI)
- `engine/`: host side (fetch, run Docker, rules, report)
- `sandbox/`: the container image and the in-container harness
- `tests/`: rule tests, plus an integration test on a harmless fixture

## License

MIT
