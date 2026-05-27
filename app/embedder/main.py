"""
Lightweight embedding microservice.
Wraps sentence-transformers so the heavy PyTorch dependency stays
in this one image and rag-api stays slim.
"""

import os
import logging
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

MODEL_NAME = os.environ.get("EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("embedder")

app = FastAPI(title="Embedding Service")

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        log.info("Loading model %s ...", MODEL_NAME)
        _model = SentenceTransformer(MODEL_NAME)
        log.info("Model loaded.")
    return _model


class EmbedRequest(BaseModel):
    texts: List[str]


class EmbedResponse(BaseModel):
    embeddings: List[List[float]]
    model: str
    dimensions: int


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME}


@app.post("/embed", response_model=EmbedResponse)
def embed(req: EmbedRequest):
    model = _get_model()
    vectors = model.encode(req.texts).tolist()
    dims = len(vectors[0]) if vectors else 0
    return EmbedResponse(embeddings=vectors, model=MODEL_NAME, dimensions=dims)
