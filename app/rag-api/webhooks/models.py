"""
Pydantic models for webhook configuration and events.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl


class EventType(str, Enum):
    """Supported webhook event types."""
    SCAN_STARTED = "scan_started"
    SCAN_STOPPED = "scan_stopped"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_SUMMARY = "scan_summary"
    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH = "finding_high"
    FINDING_EXPLOITABLE = "finding_exploitable"


class WebhookCreate(BaseModel):
    """Request model for creating a webhook."""
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable name for this webhook")
    url: str = Field(..., description="Webhook endpoint URL")
    secret: Optional[str] = Field(None, description="HMAC secret for signing payloads")
    enabled: bool = Field(True, description="Whether the webhook is active")
    event_types: List[str] = Field(
        default=["scan_completed", "finding_high"],
        description="Event types to trigger this webhook"
    )
    sources: Optional[List[str]] = Field(
        None,
        description="Filter by source scanners (nmap, nuclei, zap, etc.). None = all sources"
    )
    severities: Optional[List[str]] = Field(
        None,
        description="Filter by severity levels (critical, high, etc.). None = all severities"
    )
    max_retries: int = Field(3, ge=0, le=10, description="Maximum delivery retry attempts")
    timeout_ms: int = Field(5000, ge=1000, le=30000, description="Request timeout in milliseconds")


class WebhookUpdate(BaseModel):
    """Request model for updating a webhook."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    url: Optional[str] = None
    secret: Optional[str] = None
    enabled: Optional[bool] = None
    event_types: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    timeout_ms: Optional[int] = Field(None, ge=1000, le=30000)


class WebhookResponse(BaseModel):
    """Response model for webhook configuration."""
    id: str
    name: str
    url: str
    enabled: bool
    event_types: List[str]
    sources: Optional[List[str]]
    severities: Optional[List[str]]
    max_retries: int
    timeout_ms: int
    created_at: datetime
    updated_at: datetime
    last_success: Optional[datetime]
    failure_count: int

    class Config:
        from_attributes = True


class WebhookEventResponse(BaseModel):
    """Response model for webhook delivery events."""
    id: str
    webhook_id: str
    event_type: str
    payload: Dict[str, Any]
    status: str
    attempt: int
    response_code: Optional[int]
    error_message: Optional[str]
    created_at: datetime
    delivered_at: Optional[datetime]
    next_retry: Optional[datetime]

    class Config:
        from_attributes = True


class WebhookListResponse(BaseModel):
    """Response model for listing webhooks."""
    webhooks: List[WebhookResponse]
    total: int


class WebhookEventListResponse(BaseModel):
    """Response model for listing webhook events."""
    events: List[WebhookEventResponse]
    total: int


class WebhookTestRequest(BaseModel):
    """Request model for testing a webhook."""
    event_type: str = Field("scan_completed", description="Event type to simulate")
    payload: Optional[Dict[str, Any]] = Field(None, description="Custom payload (optional)")


class WebhookTestResponse(BaseModel):
    """Response model for webhook test results."""
    success: bool
    response_code: Optional[int]
    response_time_ms: int
    error: Optional[str]


class WebhookEmitRequest(BaseModel):
    """Internal request model for emitting webhook events."""
    event_type: str = Field(..., description="Event type (scan_completed, finding_high, etc.)")
    source: str = Field(..., description="Source scanner (nmap, nuclei, zap, etc.)")
    data: Dict[str, Any] = Field(..., description="Event payload data")
    severity: Optional[str] = Field(None, description="Severity level (for finding events)")
