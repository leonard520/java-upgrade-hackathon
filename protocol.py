from __future__ import annotations

from typing import Any, Literal, TypedDict


FrameType = Literal["task", "tool_call", "tool_result", "progress", "ack", "ask_user", "user_answer", "done", "error"]


class Frame(TypedDict, total=False):
    type: FrameType
    call_id: str
    name: str
    arguments: dict[str, Any]
    output: str
    is_error: bool
    phase: str
    text: str
    summary: str
    message: str
    goal: str
    question: str
    options: list[str]
    default: str
    answer: str