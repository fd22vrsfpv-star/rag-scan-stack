# Use an official Python runtime as a parent image
#FROM python:3.10-slim
FROM mirror.gcr.io/library/python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY scan_recommender.py /app/scan_recommender.py
COPY exploits_rag.py      /app/exploits_rag.py
COPY multi_app.py         /app/multi_app.py
COPY log_manager.py       /app/log_manager.py
COPY csv_to_json.py       /app/csv_to_json.py
COPY run_ingest.py        /app/run_ingest.py
COPY tool_kb.py           /app/tool_kb.py
COPY entrypoint.sh        /app/entrypoint.sh
COPY requirements.txt /app/requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential wget iproute2  pkg-config libpq-dev perl git && \
    rm -rf /var/lib/apt/lists/*
# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# pull ExploitDB (contains searchsploit script)
RUN mkdir -p /opt/exploitdb

RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
 && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
RUN chmod +x /opt/exploitdb/searchsploit
RUN ln -sf /opt/exploitdb /usr/share/exploitdb

# Make entrypoint executable and create searchsploit JSON directory
RUN chmod +x /app/entrypoint.sh && mkdir -p /var/lib/searchsploit



# Expose port 8013 and define environment variable
ENV OLLAMA_HOST=http://ollama:11434
ENV EMBED_MODEL=nomic-embed-text
ENV CHAT_MODEL=mistral
ENV SEARCHSPLOIT_JSON=/var/lib/searchsploit/searchsploit.json
# package path for distro-installed exploitdb
ENV EXPLOIT_ROOT=/opt/exploitdb
EXPOSE 8013

# Environment variables for ingest
ENV INGEST_LIMIT=5000
ENV SKIP_INGEST=false
ENV EXPLOITDB_CSV=/opt/exploitdb/files_exploits.csv

# Define the command to run on container start
CMD ["/app/entrypoint.sh"]


