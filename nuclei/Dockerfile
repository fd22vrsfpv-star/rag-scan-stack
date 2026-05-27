FROM docker.io/projectdiscovery/nuclei:latest AS nuclei_bin
FROM docker.io/library/python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git netcat-openbsd iproute2 dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates
WORKDIR /runner
ENV PYTHONUNBUFFERED=1
COPY nuclei/requirements.txt /runner/requirements.txt
RUN pip install --no-cache-dir -r /runner/requirements.txt
COPY nuclei/nuclei_runner.py /runner/nuclei_runner.py
COPY nuclei/validation.py /runner/validation.py
COPY nuclei/log_manager.py /runner/log_manager.py
COPY nuclei/protocol_config.py /runner/protocol_config.py
EXPOSE 8011
CMD ["python","-u","/runner/nuclei_runner.py","serve"]
