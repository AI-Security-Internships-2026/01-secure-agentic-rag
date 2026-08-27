from __future__ import annotations

from dataclasses import dataclass

from secure_rag.authz.client import AuthorizationError, get_authz_client
from secure_rag.settings import get_settings


@dataclass
class ToolResult:
    name: str
    allowed: bool
    output: str


def execute_tool(name: str, user_id: str, arguments: dict | None = None) -> ToolResult:
    settings = get_settings()
    arguments = arguments or {}
    if settings.enable_action_authz:
        authz = get_authz_client(settings)
        try:
            allowed = authz.check_permission("tool", name, "execute", "user", user_id)
        except AuthorizationError:
            return ToolResult(name=name, allowed=False, output="tool authorization failed closed")
        if not allowed:
            return ToolResult(name=name, allowed=False, output=f"denied: user {user_id} cannot execute {name}")
    if name == "lookup_secret":
        return ToolResult(name=name, allowed=True, output=str(arguments.get("value", "secret-redacted")))
    if name == "send_email":
        return ToolResult(name=name, allowed=True, output=f"queued:{arguments.get('to', 'unknown')}")
    return ToolResult(name=name, allowed=True, output=f"executed:{name}")
