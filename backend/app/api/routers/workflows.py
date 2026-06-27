"""Workflow automation endpoints: rules CRUD + manual evaluation."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_workflow_service, require_permission
from app.schemas.collab import (
    EvaluateRequest,
    EvaluateResult,
    RuleCreate,
    RuleResponse,
    RuleUpdate,
)
from app.schemas.common import Message
from app.services.workflow_service import WorkflowService

router = APIRouter(prefix="/workflows", tags=["workflow-automation"])

Dep = Annotated[WorkflowService, Depends(get_workflow_service)]


@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("workflow:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[RuleResponse]:
    rows = await svc.list(organization_id=organization_id)
    return [RuleResponse.model_validate(r) for r in rows]


@router.post("/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("workflow:manage"))],
) -> RuleResponse:
    rule = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return RuleResponse.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: RuleUpdate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("workflow:manage"))],
) -> RuleResponse:
    rule = await svc.update(rule_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return RuleResponse.model_validate(rule)


@router.delete("/rules/{rule_id}", response_model=Message)
async def delete_rule(
    rule_id: uuid.UUID,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("workflow:manage"))],
) -> Message:
    await svc.delete(rule_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Rule deleted")


@router.post("/evaluate", response_model=EvaluateResult)
async def evaluate(
    body: EvaluateRequest,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("workflow:manage"))],
) -> EvaluateResult:
    executed = await svc.evaluate(
        trigger=body.trigger, context=body.context,
        organization_id=body.organization_id, actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return EvaluateResult(executed=executed)
