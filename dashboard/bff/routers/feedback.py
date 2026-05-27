from typing import Optional
import httpx
from fastapi import APIRouter, Query
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


class FeedbackCreate(BaseModel):
    session_id: Optional[str] = None
    message_id: Optional[str] = None
    rating: int  # 1-5
    comment: Optional[str] = None
    context: Optional[dict] = None


@router.post("/api/feedback")
async def create_feedback(req: FeedbackCreate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.autogen_url}/feedback",
            json=req.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/feedback")
async def list_feedback(
    limit: int = Query(50, le=500),
    offset: int = 0,
    rating: Optional[int] = None,
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    if rating is not None:
        params["rating"] = rating
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.autogen_url}/feedback",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class FeedbackUpdate(BaseModel):
    rating: Optional[int] = None
    comment: Optional[str] = None


@router.put("/api/feedback/{feedback_id}")
async def update_feedback(feedback_id: str, req: FeedbackUpdate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.autogen_url}/feedback/{feedback_id}",
            json=req.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/feedback/export")
async def export_feedback():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/feedback/export",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)
