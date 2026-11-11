# Disposable sandbox image for Plugin Detonator.
# Standard library only: nothing is installed, so building it just pulls the
# base image. Every detonation runs with --network none, a read-only root,
# no capabilities, as a non-root user.
# Pinned by digest (multi-arch index) so every sandbox build is identical.
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

# No user account is created here: each run mounts its own account list with a
# random user name (engine/runner.py), so the image carries no fixed name.

COPY harness.py /opt/detonator/harness.py

USER 10001
ENTRYPOINT ["python", "-I", "-B", "/opt/detonator/harness.py"]
