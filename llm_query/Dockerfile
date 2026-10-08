   # Use an appropriate base image
   FROM python:3.10-slim

   # Set environment variables
   ENV OLLAMA_URL=http://ollama:11434
   ENV OLLAMA_MODEL=qwen2.5:14b

   # Install necessary dependencies.
   #
   # `litellm` powers the LiteLLM migration (Docs/plans/LITELLM_MIGRATION.md).
   # Pinned to the 1.104 minor (~=1.104.0 → >=1.104.0, <1.105); bumped from
   # 1.56.4 after the first focused-10 CVE-Bench run surfaced that 1.56.x
   # sends `max_tokens` to Azure `gpt-5-mini` which 400s with
   # "Use 'max_completion_tokens' instead" — the newer LiteLLM lines added
   # the automatic param translation for gpt-5 / o1 / o3 reasoning deploys.
   # Keep the pin narrow (minor-level) because LiteLLM ships breaking
   # changes between minors on their release cadence — bump deliberately.
   RUN pip install requests fastapi uvicorn pydantic psycopg2-binary autogen \
       anthropic azure-identity \
       'litellm~=1.104.0'
   RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl  wget iproute2 && \
    rm -rf /var/lib/apt/lists/*

   # Copy the llm_query.py script to the container
   COPY llm_query.py /app/llm_query.py
   # LiteLLM Router factory (PR 1 of the migration). Imports from
   # common.llm_settings (bind-mounted) + settings' providers list; builds a
   # LiteLLM Router WITHOUT touching the hand-rolled dispatch path. Switched
   # into _generate_text in PR 2.
   COPY litellm_router.py /app/litellm_router.py
   # Bake a build-time version stamp (see app/rag-api/Dockerfile) so a container
   # not recreated after a version bump reports IMAGE_BUILD_VERSION != BUILD_VERSION.
   ARG BUILD_VERSION=unknown
   ENV IMAGE_BUILD_VERSION=$BUILD_VERSION
   # llm_settings now comes from the ./common bind mount as
   # `common.llm_settings` — one copy, not four. See common/llm_settings.py.

   # Expose the port the app will run on
   ENV OLLAMA_URL=http://ollama:11434
   EXPOSE 8002

   # Set the working directory
   WORKDIR /app

   # Command to run the application
   CMD ["uvicorn", "llm_query:app", "--host", "0.0.0.0", "--port", "8002"]
