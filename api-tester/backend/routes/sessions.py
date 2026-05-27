"""Test session CRUD."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


def _get_store():
    from backend.main import store
    return store


class SessionCreate(BaseModel):
    name: Optional[str] = None
    collection_id: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[dict] = None


class SessionUpdate(BaseModel):
    name: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[dict] = None


@router.get("/api-test/sessions")
def list_sessions():
    return {"sessions": _get_store().list_sessions()}


@router.post("/api-test/sessions")
def create_session(body: SessionCreate):
    data = body.model_dump(exclude_none=True)
    session = _get_store().save_session(data)
    return {"ok": True, "session": session}


@router.patch("/api-test/sessions/{sid}")
def update_session(sid: str, body: SessionUpdate):
    store = _get_store()
    existing = store.get_session(sid)
    if not existing:
        raise HTTPException(404, "Session not found")
    updates = body.model_dump(exclude_none=True)
    existing.update(updates)
    session = store.save_session(existing)
    return {"ok": True, "session": session}


@router.delete("/api-test/sessions/{sid}")
def delete_session(sid: str):
    if not _get_store().delete_session(sid):
        raise HTTPException(404, "Session not found")
    return {"ok": True, "deleted": sid}
