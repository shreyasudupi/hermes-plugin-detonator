# Contributing to Detonator

Thanks for helping. Detonator is a security sandbox for Hermes Agent plugins, so the most useful
contributions are:

1. **A false alarm** on an honest plugin (Detonator flagged something normal).
2. **A missed behaviour** (a plugin did something risky and Detonator said nothing).
3. **A test report** from your machine, especially **Windows** and **macOS**. GitHub's CI can't run the
   Linux sandbox on Windows, so real-PC reports are the only way we know it works there.
4. **Code**: new rules, sharper rules, better messages, docs.

Found a way for a plugin to **escape the sandbox**, reach your real files or keys, or reach the
network? Please don't open a public issue. Report it privately, as described in [SECURITY.md](SECURITY.md).

## Ground rules

- **Never send real malware**, in an issue, a pull request or a link. Describe the behaviour, or write
  a tiny harmless example (see [Writing a harmless test plugin](#writing-a-harmless-test-plugin)).
- **Don't name other people's plugins** in public issues or pull requests. If a real catalog plugin
  is involved, say "a catalog plugin" and give the details privately (see [SECURITY.md](SECURITY.md)).
  A false alarm is not an accusation, but the issue title will read like one.
- **Rules decide, AI explains.** The verdict always comes from fixed rules in `engine/rules.py`.
  Pull requests that let a model decide or change a verdict won't be merged.
- Be kind. Many people here are new to security tools, Hermes, or both.

## Quick setup (5 minutes)

You need Python 3.11+ and Git. Docker is optional: without it, the sandbox tests are skipped and
everything else still runs.

```bash
git clone https://github.com/shreyasudupi/hermes-plugin-detonator
cd hermes-plugin-detonator
python -m pip install -r requirements-dev.txt && python -m pytest -q -rs
```

The last line is the one command to remember: it installs the test tools and runs every test.
With Docker running you should see over 100 tests pass; without Docker, the sandbox tests are
skipped with the reason "Docker not available", which is fine.

**Don't want to install anything?** Open the repo in a GitHub Codespace (green **Code** button >
**Codespaces**). The dev container in `.devcontainer/` comes with Docker and installs the test tools
for you. A Codespace is also the safe place to run plugins you don't trust.

To try your copy inside Hermes itself (Hermes installed, Docker running; macOS, Linux or a
Codespace). If you already installed Detonator with `hermes plugins install`, first move that copy
out of the way (`mv ~/.hermes/plugins/detonator ~/.hermes/plugins/detonator.bak`), otherwise the
link below lands inside it instead of replacing it:

```bash
ln -sfn "$PWD" ~/.hermes/plugins/detonator   # use your working copy as the plugin
hermes plugins enable detonator
hermes gateway stop                          # Hermes keeps old plugin code running until restart
hermes                                       # then type: /detonate check
```

Run `hermes gateway stop` again after every code change, or Hermes keeps running the old code.

## How the code fits together

| Path | What it does |
|---|---|
| `plugin.yaml`, `__init__.py`, `commands.py`, `tools.py`, `schemas.py` | The Hermes plugin: the `/detonate` command, the `hermes detonate` CLI and the two tools |
| `engine/runner.py` | Host side: fetches the plugin at an exact commit, builds and runs the Docker sandbox |
| `sandbox/harness.py` | Runs **inside** the container: plants decoys, loads the plugin, fires hooks and tools, records every action as an event |
| `engine/rules.py` | Turns those events into findings and a verdict. No model involved |
| `engine/static.py` | Reads the plugin's source without running it (the dormant-code check) |
| `engine/report.py`, `engine/diff.py` | The report, and the two-version comparison |
| `docs/RULES.md` | Every rule, why it matters, and its MITRE ATT&CK / ATLAS IDs |

The flow is: **harness records events → rules turn events into findings → report explains them.**
Most contributions only touch `engine/rules.py`, `docs/RULES.md` and `tests/test_rules.py`.

## How detection is tested (and why you don't need the private test plugins)

Detonator is checked in three layers:

1. **Rule tests** (`tests/test_rules.py`). These feed a made-up sandbox result (a list of events
   such as "read this file" or "connected to this address") straight into the rules. No plugin
   code runs, no Docker needed, and they run in a fraction of a second. **This is where new and
   changed rules are tested.**
2. **Sandbox tests** (`tests/test_sandbox_integration.py`). These run the honest example plugins
   in `tests/fixtures/` inside the real Docker sandbox and check the whole path end to end.
3. **Fake-malicious test plugins.** 23 harmless plugins that act like stealers, time bombs,
   backdoors and so on. They live in a separate **private** repository, because the Hermes catalog
   scans this repository and code that looks like a stealer, even a harmless one, doesn't belong
   here. CI runs all of them on every change and checks that every rule fires.

You can't see layer 3, and you don't need to. When you open a pull request from a fork, GitHub
doesn't give it the token for the private repository, so that CI job shows a warning instead of
running. A maintainer runs it before merging. If your change shifts a verdict there, we'll tell
you which behaviour changed (not the test plugin's code) and work it out with you.

To check a real behaviour end to end yourself, write a harmless test plugin **outside this
repository** and run it locally (next section).

## Writing a harmless test plugin

Keep it in a folder outside this repo, for example `~/detonator-scratch/my-test/`, with a
`plugin.yaml` and an `__init__.py` that has a `register(ctx)` function
(`tests/fixtures/clean_plugin/` is a good starting point). Then run:

```bash
python -m engine ~/detonator-scratch/my-test          # report in the terminal
python -m engine ~/detonator-scratch/my-test --json   # raw findings
```

Make it harmless on purpose, the same way our private test plugins are:

- **Fake secrets only.** Use obviously fake values such as `FAKE-KEY-0001`. The sandbox plants its
  own decoy keys; read those, never real ones.
- **Reserved addresses only.** For network behaviour use the documentation ranges `192.0.2.x`,
  `198.51.100.x` or `203.0.113.x`, which never route anywhere. (The sandbox has no network anyway.)
- **Harmless commands only.** If the behaviour is "runs a shell command", run `true`.
- **Run it in the sandbox, not directly.** `python -m engine` puts it in the container. Don't import
  or run it on your own machine.

If it shows a problem, paste the **report** (and, if you like, a short description of what the
plugin does) into an issue. Please don't attach plugin code that imitates malware; we'll rebuild it
privately if we need to.

## Adding or changing a rule

1. **Add the rule** to the `RULES` table at the top of `engine/rules.py`: a plain-words `why`, plus
   the MITRE ATT&CK and ATLAS technique IDs it resembles.
2. **Add the logic** in `_evaluate()` in the same file. Look at a similar rule first; most read
   events with `of("<kind>")` and call `add(Finding(...))` with a severity and a short title.
3. **Pick the severity carefully.** It sets the verdict: critical → DANGEROUS, high → SUSPICIOUS,
   medium → REVIEW, low and info don't change it. If honest plugins commonly do this thing, it
   should not be above medium.
4. **Document it** with a row in `docs/RULES.md`. A test fails if the rule, its `why` text or its
   technique IDs are missing there, so you can't forget.
5. **Test it** in `tests/test_rules.py` using the `base()` and `ev()` helpers at the top: one test
   that it fires, and one that a similar honest action does **not** fire it.
6. Run `python -m pytest -q -rs`.

Plain words matter: the `why` and the title are what users read. Say what the plugin did and why
it matters, without jargon.

## Opening a pull request

- Branch from `main`, keep the pull request to one change, and fill in the template.
- CI runs four jobs: the tests on Linux (with real Docker runs), the tests on Windows, Hermes's own
  `hermes plugins validate` (the same check the catalog runs) and the private test plugins
  (skipped on forks, see above).
- **Changing the version?** Update `plugin.yaml` **and** the README: the "Current version" line at the
  top and a new first entry under **Versions**. A test checks they match. Leave version bumps to the
  maintainer unless asked.
- Don't add fake-malicious code, decoy secrets or real plugin names to this repository.

## Testing on your machine (community testers)

We especially need runs on **Windows** (Docker Desktop with WSL 2) and **macOS**. You don't need
to write code:

1. Install it with the steps in [docs/QUICKSTART.md](docs/QUICKSTART.md).
2. Type `/detonate check`, then run Detonator on any plugin you like at an exact commit.
3. Open a **Test report** issue and fill in the form: your OS, Docker setup, Hermes version,
   terminal or Desktop app, and what happened.

Known rough edges, so you don't report them twice:

- **Windows** needs WSL 2: run `wsl --install` in PowerShell as administrator, then restart.
- **Desktop app**: the very first `/detonate` can say "request timed out after 30s" while the
  sandbox image builds. Run it again and it works. This is expected.

## License

By contributing you agree that your contribution is released under the [MIT License](LICENSE).
