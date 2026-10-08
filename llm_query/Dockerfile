   # Use an appropriate base image
   FROM python:3.10-slim

   # Set environment variables
   ENV OLLAMA_URL=http://ollama:11434
   ENV OLLAMA_MODEL=qwen2.5:14b

   # Install necessary dependencies.
   #
   # `litellm` is added for the LiteLLM migration (Docs/plans/LITELLM_MIGRATION.md).
   # PR 1 ships the router FACTORY in parallel to the hand-rolled dispatch; the
   # swap of `_generate_text` to `router.completion` lands in PR 2. Pinned to the
   # 1.56.x line referenced in the plan — the version-pin matters because LiteLLM
   # has rapid releases and the azure_ai/anthropic provider shape stabilised in
   # that window. Bump deliberately.
   RUN pip install requests fastapi uvicorn pydantic psycopg2-binary autogen \
       anthropic azure-identity \
       'litellm==1.56.4'
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
