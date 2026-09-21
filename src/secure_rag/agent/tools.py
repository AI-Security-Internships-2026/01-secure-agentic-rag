from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from secure_rag.audit.events import emit
from secure_rag.authz.client import AuthorizationError, get_authz_client
from secure_rag.settings import get_settings


class SendEmailArgs(BaseModel):
    to_address: str = Field(..., description="Recipient email address")
    body: str = Field(..., description="Email body content")


class SafeFileReadArgs(BaseModel):
    path: str = Field(..., description="Safe file path to read")


class LookupSecretArgs(BaseModel):
    value: str = Field(..., description="Secret key or identifier")


TOOL_SCHEMAS: dict[str, type[BaseModel]] = {
    "send_email": SendEmailArgs,
    "safe_file_read": SafeFileReadArgs,
    "lookup_secret": LookupSecretArgs,
}

REGISTERED_TOOL_POS_ARGS: dict[str, list[str]] = {
    "send_email": ["to_address", "body"],
    "safe_file_read": ["path"],
    "lookup_secret": ["value"],
}


@dataclass
class ToolResult:
    name: str
    allowed: bool
    output: str
    arguments: dict[str, Any] = field(default_factory=dict)


def parse_tool_calls(
    text: str,
    user_id: str = "",
    tenant_id: str = "",
) -> list[dict[str, Any]]:
    """Parse <<<TOOL_CALL: ...>>> tokens from text."""
    if not text or "<<<TOOL_CALL:" not in text:
        return []

    pattern = re.compile(r"<<<TOOL_CALL:\s*([\s\S]*?)\s*>>>")
    matches = list(pattern.finditer(text))

    raw_tags = re.findall(r"<<<TOOL_CALL:", text)
    if len(raw_tags) > len(matches):
        emit(
            "tool.parse.malformed",
            user_id=user_id,
            tenant_id=tenant_id,
            extra={"error": "unclosed_tool_call_tag", "raw": text},
        )

    tool_calls: list[dict[str, Any]] = []

    for match in matches:
        raw_content = match.group(1).strip()
        parsed = False

        # Attempt 1: JSON payload
        if raw_content.startswith("{") and raw_content.endswith("}"):
            try:
                data = json.loads(raw_content)
                name = data.get("name") or data.get("action") or data.get("tool")
                args = data.get("arguments") or data.get("args") or {}
                if name and isinstance(args, dict):
                    if "to" in args and "to_address" not in args:
                        args["to_address"] = args["to"]
                    tool_calls.append({"name": str(name), "arguments": args})
                    parsed = True
            except Exception:
                pass

        # Attempt 2: Python function call syntax via AST
        if not parsed:
            try:
                tree = ast.parse(raw_content, mode="eval")
                if isinstance(tree.body, ast.Call):
                    func_node = tree.body.func
                    func_name = ""
                    if isinstance(func_node, ast.Name):
                        func_name = func_node.id
                    elif isinstance(func_node, ast.Attribute):
                        func_name = func_node.attr

                    if func_name:
                        kwargs: dict[str, Any] = {}
                        for kw in tree.body.keywords:
                            if kw.arg:
                                kwargs[kw.arg] = ast.literal_eval(kw.value)

                        pos_args = [ast.literal_eval(arg) for arg in tree.body.args]
                        param_names = REGISTERED_TOOL_POS_ARGS.get(func_name, [])
                        for i, val in enumerate(pos_args):
                            if i < len(param_names):
                                kwargs[param_names[i]] = val
                            else:
                                kwargs[f"arg_{i}"] = val

                        if "to" in kwargs and "to_address" not in kwargs:
                            kwargs["to_address"] = kwargs["to"]

                        tool_calls.append({"name": func_name, "arguments": kwargs})
                        parsed = True
            except Exception:
                pass

        if not parsed:
            emit(
                "tool.parse.malformed",
                user_id=user_id,
                tenant_id=tenant_id,
                extra={"raw_content": raw_content},
            )

    return tool_calls


def execute_tool(
    name: str,
    user_id: str,
    arguments: dict | None = None,
    *,
    check_authz: bool | None = None,
    tenant_id: str = "",
) -> ToolResult:
    """Execute tool with action-time ReBAC reference monitor check."""
    settings = get_settings()
    arguments = dict(arguments or {})
    enforce = settings.enable_action_authz if check_authz is None else check_authz

    if enforce:
        authz = get_authz_client(settings)
        try:
            allowed = authz.check_permission("tool", name, "execute", "user", user_id)
        except AuthorizationError:
            emit(
                "tool.exec.denied",
                user_id=user_id,
                document_id=name,
                tenant_id=tenant_id,
                extra={"tool": name, "arguments": arguments, "reason": "authz_error"},
            )
            return ToolResult(
                name=name,
                allowed=False,
                output="tool authorization failed closed",
                arguments=arguments,
            )
        if not allowed:
            emit(
                "tool.exec.denied",
                user_id=user_id,
                document_id=name,
                tenant_id=tenant_id,
                extra={"tool": name, "arguments": arguments, "reason": "unauthorized"},
            )
            return ToolResult(
                name=name,
                allowed=False,
                output=f"Tool call denied by policy: user {user_id} cannot execute {name}",
                arguments=arguments,
            )

    emit(
        "tool.exec.allowed",
        user_id=user_id,
        document_id=name,
        tenant_id=tenant_id,
        extra={"tool": name, "arguments": arguments},
    )

    if name == "lookup_secret":
        return ToolResult(
            name=name,
            allowed=True,
            output=str(arguments.get("value", "secret-redacted")),
            arguments=arguments,
        )
    if name == "send_email":
        to_addr = arguments.get("to_address") or arguments.get("to", "unknown")
        return ToolResult(
            name=name,
            allowed=True,
            output=f"queued:{to_addr}",
            arguments=arguments,
        )
    if name == "safe_file_read":
        path_arg = arguments.get("path", "")
        return ToolResult(
            name=name,
            allowed=True,
            output=f"file_read:{path_arg}",
            arguments=arguments,
        )
    return ToolResult(
        name=name,
        allowed=True,
        output=f"executed:{name}",
        arguments=arguments,
    )

