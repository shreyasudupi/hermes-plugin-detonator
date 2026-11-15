# Detonator quickstart

From nothing to your first sandbox run, step by step. If you already have Hermes and Docker
running, skip to [step 3](#3-install-detonator-one-command).

**What Detonator does:** you name a Hermes plugin (by its catalog name or GitHub link). It runs that plugin inside
a throwaway Docker container with no network and fake secrets, then tells you what the plugin
actually did (read keys, reached for the network, ran commands, planted start-up files...).
It always asks before running anything.

## 1. Install Docker

Detonator runs plugins inside a Docker container, so Docker must be installed **and running**.

| Your computer | What to install |
|---|---|
| **macOS** | [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/) (Colima and OrbStack also work). Open it and wait until it says it's running. |
| **Windows** | First open PowerShell **as administrator** and run `wsl --install`, then restart the PC. Then install [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) and keep it on **Linux containers** (the default). |
| **Linux** | [Docker Engine](https://docs.docker.com/engine/install/), then `sudo systemctl start docker`. To use it without `sudo`, add yourself to the `docker` group and log out and back in (do this only on your own machine). |

## 2. Install Hermes Agent

Follow the official [Hermes installation guide](https://hermes-agent.nousresearch.com/docs/getting-started/installation).
Check it worked with `hermes --version`. Detonator needs Hermes 0.23.0 or newer.

## 3. Install Detonator (one command)

**macOS, Linux, or Windows PowerShell 7:**

```bash
hermes plugins install detonator && hermes plugins enable detonator && hermes gateway stop
```

**Windows PowerShell 5** (the one built into Windows, which doesn't understand `&&`):

```powershell
hermes plugins install detonator; hermes plugins enable detonator; hermes gateway stop
```

If it says `'detonator' is not in the Hermes plugin catalog`, run `hermes update` and try again:
Hermes from before Nov 9, 2026 cannot read the online catalog, so it misses newer plugins.

What the three parts do:

1. `hermes plugins install detonator` downloads Detonator from the Hermes plugin catalog into your
   Hermes plugins folder. Use the name `detonator`, not the GitHub repo: Hermes's install scan
   blocks Detonator's repo because its docs and tests are full of the security words it scans for.
2. `hermes plugins enable detonator` switches it on. Hermes plugins are off until you enable them.
3. `hermes gateway stop` stops Hermes's background plugin host, so it loads Detonator next time
   you start Hermes. Nothing is lost; it starts again on its own.

`hermes plugins install detonator` installs the version the Hermes catalog has reviewed and pinned
(Nous reviews every update). **Want a different tagged version?** Pick a tag on the
[Releases page](https://github.com/shreyasudupi/hermes-plugin-detonator/releases) and install that
copy yourself (macOS or Linux; replace `<tag>`):

```bash
git clone --branch <tag> --depth 1 https://github.com/shreyasudupi/hermes-plugin-detonator ~/.hermes/plugins/detonator
hermes plugins enable detonator && hermes gateway stop
```

We don't offer a `curl ... | bash` installer on purpose: a security tool shouldn't ask you to run a
script you haven't read. These are Hermes's own commands.

## 4. Check Docker is ready

Start the chat with `hermes`. (The chat needs an AI provider set up first; `hermes model` does
that. `/detonate` itself never uses the model. No provider? Every command below also works from the
terminal as `hermes detonate ...`, without one.) Then type:

```
/detonate check
```

This only asks Docker for its status. It runs nothing. If something needs fixing, it says what;
the [Docker problems](../README.md#docker-problems) table in the README has the details.

## 5. Your first run

Find a plugin you are thinking of installing, for example with `hermes plugins search weather`.
Then, in the Hermes chat, test it by its name:

```
/detonate <name>
```

This tests exactly what `hermes plugins install <name>` would install: the same repo, commit and
folder. You don't need to know any commit SHA. For a plugin that is not in the catalog, give its
GitHub page instead: `/detonate https://github.com/owner/repo` tests its newest commit (add the
folder after it if the plugin lives in a subfolder of the repo).

Detonator asks first, and you choose between two tests:

- **Run full test**: the inside and outside monitors. It also catches plugins that hide what they
  do or fake a clean result, and takes a second or two longer.
- **Run quick test**: the inside monitor only. A little faster, but a plugin that hides what it does
  or fakes its own report can fool it.

Every report starts with the test mode it used, and a quick test's report lists what it did not
check. The very first run builds the sandbox image, which
takes a minute or two; after that a run takes seconds.

> **Desktop app:** the very first run can say "request timed out after 30s" while the image builds,
> because Desktop gives a command 30 seconds. Just run the same command again. Or do the first run in
> the `hermes` terminal chat, which has no limit.

You get a verdict (`DANGEROUS`, `SUSPICIOUS`, `REVIEW`, `NO_FINDINGS` or `ERROR`), the full commit
it tested, and a list of findings, each with why it matters. The full report is saved under
`~/.hermes/plugin-data/detonator/reports/`.

To have your model explain the report in plain words, ask Hermes:
"Use the detonator_report tool to explain my latest Detonator report". The model explains; it never
changes the verdict.

## 6. Before you update a plugin

`hermes plugins check-updates` lists plugins with an update. Before you apply one, compare the
version you have with the new one:

```
/detonate update <name>
```

Detonator reads which commit you have installed, runs it and the version an update would install,
and shows what the new version does that the old one didn't. (Comparing two commits of your own
choice also works: `/detonate <owner/repo> <old-sha> <new-sha>`.)

## 7. Test an MCP server

MCP servers you add under `mcp_servers:` in Hermes's config give the agent new tools. To test one
before you trust it, use its name from the config:

```
/detonate-mcp <server-name>
```

Detonator downloads its npm or PyPI package (install scripts off), starts it in the sandbox with fake
keys, calls every tool the way Hermes would, and reports what the server told the model and what it
did. A server whose code is in a folder works too: `/detonate-mcp <folder>`, with an
`mcp-server.yaml` next to it (see the README).

## Next

- What every finding means: [docs/RULES.md](RULES.md)
- Something wrong, or a run on Windows or macOS to share? See [CONTRIBUTING.md](../CONTRIBUTING.md).
  Test reports from real machines help a lot.
- Found a way out of the sandbox? Report it privately: [SECURITY.md](../SECURITY.md).

A clean report is evidence, not proof that a plugin is safe. See the README for the known limits.
