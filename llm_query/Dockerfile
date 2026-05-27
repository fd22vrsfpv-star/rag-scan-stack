   # Use an appropriate base image
   FROM python:3.10-slim

   # Set environment variables
   ENV OLLAMA_URL=http://ollama:11434
   ENV OLLAMA_MODEL=qwen2.5:14b

   # Install necessary dependencies
   RUN pip install requests fastapi uvicorn pydantic psycopg2-binary autogen
   RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl  wget iproute2 && \
    rm -rf /var/lib/apt/lists/*

   # Copy the llm_query.py script to the container
   COPY llm_query.py /app/llm_query.py

   # Expose the port the app will run on
   ENV OLLAMA_URL=http://ollama:11434
   EXPOSE 8002

   # Set the working directory
   WORKDIR /app

   # Command to run the application
   CMD ["uvicorn", "llm_query:app", "--host", "0.0.0.0", "--port", "8002"]
