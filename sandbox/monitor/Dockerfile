# Detonator's outside monitor: the strace tracer and the fake internet.
# Never runs plugin code. Built once, next to the sandbox image; needs the
# internet once at build time to install strace from Debian.
# Same pinned base image as the sandbox.
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

RUN apt-get update && apt-get install -y --no-install-recommends strace && apt-get clean

COPY tracer.py sink.py /opt/detonator-monitor/
