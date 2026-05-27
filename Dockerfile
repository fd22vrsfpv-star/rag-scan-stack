FROM python:3.12-slim

# Install necessary dependencies
RUN pip install requests fastapi uvicorn pydantic psycopg2-binary autogen

WORKDIR /app
