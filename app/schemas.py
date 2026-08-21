from pydantic import BaseModel
from typing import Optional, List, Any
import datetime


class ScanRequest(BaseModel):
    url: str


class ScanJobOut(BaseModel):
    id: str
    url: str
    status: str
    error_message: Optional[str] = None
    accessibility_score: Optional[int] = None
    security_score: Optional[int] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


class ViolationOut(BaseModel):
    rule_id: str
    impact: str
    description: str
    help_text: str
    help_url: str
    node_count: int
    nodes: Any

    class Config:
        from_attributes = True


class SecurityFindingOut(BaseModel):
    check_id: str
    category: str
    severity: str
    title: str
    description: str
    passed: bool

    class Config:
        from_attributes = True


class ScanResultsOut(BaseModel):
    job: ScanJobOut
    violations: List[ViolationOut]
    security_findings: List[SecurityFindingOut]
