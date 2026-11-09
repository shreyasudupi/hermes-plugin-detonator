"""Developer CLI: python -m engine <plugin-dir> | --repo owner/name --sha <40-hex>

For use inside a disposable environment (Codespace / CI) while developing.
Inside Hermes, users go through the plugin's own approval-gated entry points.
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import report, rules, runner


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m engine")
    ap.add_argument("path", nargs="?", help="local plugin directory (contains plugin.yaml)")
    ap.add_argument("--repo", help="GitHub owner/name")
    ap.add_argument("--sha", help="full 40-character commit SHA")
    ap.add_argument("--subdir", help="plugin subdirectory inside the repo")
    ap.add_argument("--json", action="store_true", help="print raw evaluation JSON")
    ap.add_argument("--raw", help="write raw harness result to this file")
    args = ap.parse_args(argv)

    try:
        with tempfile.TemporaryDirectory(prefix="detonator-src-") as work:
            if args.repo:
                target = runner.fetch_github(args.repo, args.sha, Path(work), args.subdir)
            elif args.path:
                target = runner.local_target(args.path)
            else:
                ap.error("give a plugin path or --repo/--sha")
            raw = runner.detonate(target)
    except runner.DetonatorError as exc:
        print(f"detonator: {exc}", file=sys.stderr)
        return 2

    if args.raw:
        Path(args.raw).write_text(json.dumps(raw, indent=1))
    evaluation = rules.evaluate(raw)
    if args.json:
        print(json.dumps(evaluation, indent=1))
    else:
        print(report.render(target.label, evaluation, raw))
    return {"DANGEROUS": 3, "SUSPICIOUS": 3, "ERROR": 2}.get(evaluation["verdict"], 0)


if __name__ == "__main__":
    sys.exit(main())
