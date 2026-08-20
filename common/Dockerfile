# Shared base image for the Python services.
#
# 13 of the service images already start FROM python:3.12-slim and then carry
# their own copy of common/ — validation.py alone existed in seven places, and
# one had drifted with a real fix stranded in it. Baking the shared code into a
# base image puts it in ONE place with no runtime dependency: unlike a bind
# mount it survives `docker run` without compose, and unlike a shared API
# container there is no network call in the path of a security check.
#
# Build order matters: this must exist before any dependent image builds.
# scripts/build-base-image.sh does that, and setup.sh calls it.
FROM python:3.12-slim

# Shared modules live on the default import path, so services `import validation`
# or `from tool_job import run_tool_job` with no sys.path juggling.
COPY validation.py sql_utils.py structured_logger.py tool_job.py /usr/local/lib/python3.12/site-packages/

LABEL org.opencontainers.image.title="rag-common" \
      org.opencontainers.image.description="Shared Python modules for rag-scan-stack services"
