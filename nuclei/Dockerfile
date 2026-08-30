FROM docker.io/projectdiscovery/nuclei:latest AS nuclei_bin
# Shared modules (validation, sql_utils, structured_logger, tool_job) come
# from this base — see common/Dockerfile. Build it first with
# scripts/build-base-image.sh; compose does not order builds by FROM.
FROM rag-common:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git netcat-openbsd iproute2 dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates
WORKDIR /runner
ENV PYTHONUNBUFFERED=1
COPY nuclei/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt
COPY nuclei/nuclei_runner.py /runner/nuclei_runner.py
# validation.py now comes from the rag-common base image; the per-service
# copy was deleted. Seven copies existed and one had drifted with a real
# fix stranded in it.
COPY nuclei/log_manager.py /runner/log_manager.py
COPY nuclei/protocol_config.py /runner/protocol_config.py
EXPOSE 8011
CMD ["python","-u","/runner/nuclei_runner.py","serve"]
