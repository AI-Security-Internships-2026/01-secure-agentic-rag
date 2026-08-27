from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib import resources
from typing import Iterable, Protocol

from secure_rag.settings import Settings, get_settings

logger = logging.getLogger("secure_rag.authz")

RelationTuple = tuple[str, str, str, str, str]


class AuthorizationError(RuntimeError):
    """Raised when authorization cannot be evaluated safely."""


class AuthzClient(Protocol):
    def write_relationships(self, tuples: list[RelationTuple]) -> None: ...
    def delete_relationships(self, resource_type: str, resource_id: str | None = None) -> None: ...
    def check_permission(
        self, resource_type: str, resource_id: str, permission: str, subject_type: str, subject_id: str
    ) -> bool: ...
    def lookup_resources(self, resource_type: str, permission: str, subject_type: str, subject_id: str) -> list[str]: ...
    def ensure_schema(self) -> None: ...


def _load_schema() -> str:
    return resources.files("secure_rag.authz").joinpath("schema.zed").read_text(encoding="utf-8")


@dataclass
class SpiceDBSimulator:
    """In-memory ReBAC used only when APP_ENV=test."""

    relationships: set[RelationTuple] = field(default_factory=set)

    def ensure_schema(self) -> None:
        return

    def write_relationships(self, tuples: list[RelationTuple]) -> None:
        self.relationships.update(tuples)

    def delete_relationships(self, resource_type: str, resource_id: str | None = None) -> None:
        if resource_id:
            self.relationships = {
                t
                for t in self.relationships
                if not (t[0] == resource_type and t[1] == resource_id)
                and not (t[0] == "chunk" and t[2] == "parent_document" and t[3] == resource_type and t[4] == resource_id)
            }
        else:
            self.relationships = {t for t in self.relationships if t[0] != resource_type}

    def check_permission(
        self, resource_type: str, resource_id: str, permission: str, subject_type: str, subject_id: str
    ) -> bool:
        if resource_type == "tenant" and permission == "view":
            return (resource_type, resource_id, "member", subject_type, subject_id) in self.relationships
        if resource_type == "tool" and permission == "execute":
            return (resource_type, resource_id, "caller", subject_type, subject_id) in self.relationships
        if resource_type == "document":
            allowed = {"owner"}
            if permission == "view":
                allowed.update({"viewer", "editor"})
            elif permission == "edit":
                allowed.add("editor")
            for rel in allowed:
                if (resource_type, resource_id, rel, subject_type, subject_id) in self.relationships:
                    return True
            if permission == "view":
                parents = [
                    t[4]
                    for t in self.relationships
                    if t[0] == "document" and t[1] == resource_id and t[2] == "tenant" and t[3] == "tenant"
                ]
                return any(self.check_permission("tenant", tenant_id, "view", subject_type, subject_id) for tenant_id in parents)
            return False
        if resource_type == "chunk" and permission == "view":
            parents = [
                t[4]
                for t in self.relationships
                if t[0] == "chunk" and t[1] == resource_id and t[2] == "parent_document" and t[3] == "document"
            ]
            return any(self.check_permission("document", doc_id, "view", subject_type, subject_id) for doc_id in parents)
        return False

    def lookup_resources(self, resource_type: str, permission: str, subject_type: str, subject_id: str) -> list[str]:
        ids = {t[1] for t in self.relationships if t[0] == resource_type}
        if resource_type == "document":
            ids.update({t[4] for t in self.relationships if t[3] == "document"})
        return [r_id for r_id in sorted(ids) if self.check_permission(resource_type, r_id, permission, subject_type, subject_id)]


class RealSpiceDBClient:
    def __init__(self, endpoint: str, preshared_key: str) -> None:
        from authzed.api.v1 import Client
        from grpcutil import insecure_bearer_token_credentials

        self.client = Client(endpoint, insecure_bearer_token_credentials(preshared_key))

    def ensure_schema(self) -> None:
        from authzed.api.v1 import WriteSchemaRequest

        self.client.WriteSchema(WriteSchemaRequest(schema=_load_schema()))

    def write_relationships(self, tuples: list[RelationTuple]) -> None:
        from authzed.api.v1 import ObjectReference, Relationship, RelationshipUpdate, SubjectReference, WriteRelationshipsRequest

        updates = []
        for r_type, r_id, rel, s_type, s_id in tuples:
            updates.append(
                RelationshipUpdate(
                    operation=RelationshipUpdate.Operation.OPERATION_CREATE,
                    relationship=Relationship(
                        resource=ObjectReference(object_type=r_type, object_id=r_id),
                        relation=rel,
                        subject=SubjectReference(object=ObjectReference(object_type=s_type, object_id=s_id)),
                    ),
                )
            )
        self.client.WriteRelationships(WriteRelationshipsRequest(updates=updates))

    def delete_relationships(self, resource_type: str, resource_id: str | None = None) -> None:
        from authzed.api.v1 import DeleteRelationshipsRequest, RelationshipFilter, SubjectFilter

        self.client.DeleteRelationships(
            DeleteRelationshipsRequest(
                relationship_filter=RelationshipFilter(resource_type=resource_type, optional_resource_id=resource_id)
            )
        )
        if resource_type == "document" and resource_id:
            self.client.DeleteRelationships(
                DeleteRelationshipsRequest(
                    relationship_filter=RelationshipFilter(
                        resource_type="chunk",
                        optional_relation="parent_document",
                        optional_subject_filter=SubjectFilter(subject_type="document", optional_subject_id=resource_id),
                    )
                )
            )

    def check_permission(
        self, resource_type: str, resource_id: str, permission: str, subject_type: str, subject_id: str
    ) -> bool:
        from authzed.api.v1 import (
            CheckPermissionRequest,
            CheckPermissionResponse,
            Consistency,
            ObjectReference,
            SubjectReference,
        )

        try:
            resp = self.client.CheckPermission(
                CheckPermissionRequest(
                    resource=ObjectReference(object_type=resource_type, object_id=resource_id),
                    permission=permission,
                    subject=SubjectReference(object=ObjectReference(object_type=subject_type, object_id=subject_id)),
                    consistency=Consistency(fully_consistent=True),
                )
            )
            return resp.permissionship == CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
        except Exception as exc:
            logger.error("SpiceDB check failed: %s", exc)
            raise AuthorizationError("authorization check failed") from exc

    def lookup_resources(self, resource_type: str, permission: str, subject_type: str, subject_id: str) -> list[str]:
        from authzed.api.v1 import Consistency, LookupResourcesRequest, SubjectReference, ObjectReference

        try:
            request = LookupResourcesRequest(
                resource_object_type=resource_type,
                permission=permission,
                subject=SubjectReference(object=ObjectReference(object_type=subject_type, object_id=subject_id)),
                consistency=Consistency(fully_consistent=True),
            )
            return [resp.resource_object_id for resp in self.client.LookupResources(request)]
        except Exception as exc:
            logger.error("SpiceDB lookup failed: %s", exc)
            raise AuthorizationError("authorization lookup failed") from exc


_client: AuthzClient | None = None


def get_authz_client(settings: Settings | None = None) -> AuthzClient:
    global _client
    if _client is not None:
        return _client
    settings = settings or get_settings()
    if settings.allow_simulator:
        _client = SpiceDBSimulator()
        _client.ensure_schema()
        return _client
    try:
        live = RealSpiceDBClient(settings.spicedb_endpoint, settings.spicedb_preshared_key)
        live.ensure_schema()
        _client = live
        return _client
    except Exception as exc:
        if settings.spicedb_fail_closed:
            raise AuthorizationError("SpiceDB is required and unavailable") from exc
        raise

def reset_authz_client() -> None:
    global _client
    _client = None


def authorize_or_deny(client: AuthzClient, *args) -> bool:
    try:
        return client.check_permission(*args)
    except AuthorizationError:
        return False
