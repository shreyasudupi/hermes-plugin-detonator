"""Windows smoke test for CI: the host side of /detonate, up to the point Docker starts.

GitHub's Windows machines only run Windows containers, so the Linux sandbox itself can't run
there. This checks the parts that can: the Docker readiness message, a real git fetch with
Windows git, and the docker run command built from real Windows temp paths.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import runner  # noqa: E402

REPO = "shreyasudupi/hermes-plugin-detonator"
SHA = "342db6b77ae98ae75aabd4c27047568535d52c9a"  # v0.2.2


def main() -> int:
    report = runner.docker_check()
    print(report)
    if "Linux containers" not in report and "not ready" not in report:
        print("FAIL: expected a 'switch to Linux containers' or 'not ready' message on this runner")
        return 1
    with tempfile.TemporaryDirectory(prefix="detonator-") as tmp:
        tmp = Path(tmp)
        target = runner.fetch_github(REPO, SHA, tmp)
        print(f"ok   fetched {REPO}@{SHA[:7]} into {target.path}")
        if not (target.path / "plugin.yaml").is_file():
            print("FAIL: plugin.yaml missing after fetch")
            return 1
        cmd = runner.docker_run_cmd("img:test", target.path, tmp / "in", tmp / "out", runner.random_world(),
                                    tmp / "etc")
        mounts = [cmd[i + 1] for i, c in enumerate(cmd) if c == "-v"]
        print("ok   mounts: " + " | ".join(mounts))
        if not mounts[0].startswith(str(target.path) + ":/plugin"):
            print("FAIL: plugin mount is wrong")
            return 1
    print("ok   Windows host checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
