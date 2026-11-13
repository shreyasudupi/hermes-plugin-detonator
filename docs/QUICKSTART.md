# Detonator quickstart

From nothing to your first sandbox run, step by step. If you already have Hermes and Docker
running, skip to [step 3](#3-install-detonator-one-command).

**What Detonator does:** you give it a Hermes plugin at an exact commit. It runs that plugin inside
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
hermes plugins install shreyasudupi/hermes-plugin-detonator && hermes plugins enable detonator && hermes gateway stop
```

**Windows PowerShell 5** (the one built into Windows, which doesn't understand `&&`):

```powershell
hermes plugins install shreyasudupi/hermes-plugin-detonator; hermes plugins enable detonator; hermes gateway stop
```

What the three parts do:

1. `hermes plugins install` downloads Detonator into your Hermes plugins folder.
2. `hermes plugins enable detonator` switches it on. Hermes plugins are off until you enable them.
3. `hermes gateway stop` stops Hermes's background plugin host, so it loads Detonator next time
   you start Hermes. Nothing is lost; it starts again on its own.

`hermes plugins install` takes the latest code on the `main` branch, which only changes through
reviewed pull requests with CI. **Want one exact version instead?** Pick a tag on the
[Releases page](https://github.com/shreyasudupi/hermes-plugin-detonator/releases) and install that
copy yourself (macOS or Linux; replace `<tag>`):

```bash
git clone --branch <tag> --depth 1 https://github.com/shreyasudupi/hermes-plugin-detonator ~/.hermes/plugins/detonator
hermes plugins enable detonator && hermes gateway stop
```

We don't offer a `curl ... | bash` installer on purpose: a security tool shouldn't ask you to run a
script you haven't read. These are Hermes's own commands.

## 4. Check Docker is ready

Start the chat with `hermes`, then type:

```
/detonate check
```

This only asks Docker for its status. It runs nothing. If something needs fixing, it says what;
the [Docker problems](../README.md#docker-problems) table in the README has the details.

## 5. Your first run

Pick any Hermes plugin on GitHub and copy the full 40-character commit SHA you want to test
(on GitHub: open the repository, click the commits link, then the copy button next to a commit).
In the Hermes chat:

```
/detonate <owner/repo> <40-char-sha> [subdir]
```

Detonator asks first. Choose the run option: **Run in sandbox** in v0.2.3; from v0.3.0 the
prompt offers **Run full test (recommended)** or **Run quick test** (faster, but skips the outside
monitor). The very first run builds the sandbox image, which
takes a minute or two; after that a run takes seconds.

> **Desktop app:** the very first run can say "request timed out after 30s" while the image builds,
> because Desktop gives a command 30 seconds. Just run the same command again. Or do the first run in
> the `hermes` terminal chat, which has no limit.

You get a verdict (`DANGEROUS`, `SUSPICIOUS`, `REVIEW`, `NO_FINDINGS` or `ERROR`) and a list of
findings, each with why it matters. The full report is saved under
`~/.hermes/plugin-data/detonator/reports/`.

To have your model explain the report in plain words, ask Hermes:
"Use the detonator_report tool to explain my latest Detonator report". The model explains; it never
changes the verdict.

## 6. Before you update a plugin

Compare the version you have with the new one. Detonator shows what the new version does that the
old one didn't:

```
/detonate <owner/repo> <old-sha> <new-sha> [subdir]
```

## Next

- What every finding means: [docs/RULES.md](RULES.md)
- Something wrong, or a run on Windows or macOS to share? See [CONTRIBUTING.md](../CONTRIBUTING.md).
  Test reports from real machines help a lot.
- Found a way out of the sandbox? Report it privately: [SECURITY.md](../SECURITY.md).

A clean report is evidence, not proof that a plugin is safe. See the README for the known limits.
