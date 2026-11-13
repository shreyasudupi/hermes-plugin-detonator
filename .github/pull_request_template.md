## What this changes

<!-- One or two sentences, in plain words. Link the issue if there is one: "Fixes #12". -->

## Why

<!-- The problem it solves, or the behaviour it catches or stops flagging. -->

## How I tested it

<!-- For example: "python -m pytest -q -rs: all pass", plus anything you ran by hand. -->

## Checklist

- [ ] `python -m pytest -q -rs` passes on my machine
- [ ] New or changed rules have a row in `docs/RULES.md` and a test in `tests/test_rules.py` (one that fires, one that doesn't)
- [ ] No real malware, real secrets, fake-malicious plugin code or other people's plugin names added
- [ ] The verdict still comes only from rules, never from a model
- [ ] If the version changed: `plugin.yaml` and the README ("Current version" line and Versions list) both updated
