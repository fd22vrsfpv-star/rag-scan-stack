# multi_app.py
# Mount the RAG/searchsploit router on top of the existing scan_recommender FastAPI app.
import logging

import scan_recommender as sr

# Try to import and mount the RAG router; log an error if it fails so the main app still runs.
try:
    from exploits_rag import rag_router
    sr.app.include_router(rag_router)
except Exception as e:
    logging.getLogger("uvicorn.error").exception("Failed to include rag_router: %s", e)

# Export the combined app for uvicorn
app = sr.app
