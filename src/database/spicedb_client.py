import os
import logging
from typing import List, Tuple, Set, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SpiceDBClient")

try:
    from authzed.api.v1 import (
        Client,
        CheckPermissionRequest,
        CheckPermissionResponse,
        LookupResourcesRequest,
        WriteRelationshipsRequest,
        DeleteRelationshipsRequest,
        ObjectReference,
        SubjectReference,
        Relationship,
        RelationshipUpdate,
        RelationshipFilter,
        WriteSchemaRequest,
        SubjectFilter,
        Consistency,
    )
    from grpcutil import insecure_bearer_token_credentials
    HAS_AUTHZED = True
except ImportError:
    HAS_AUTHZED = False
    logger.warning("authzed package not installed or import failed. SpiceDB client will run in simulator mode.")

class SpiceDBSimulator:
    """
    In-memory Zanzibar-style permission simulator for SpiceDB.
    Maintains a set of relationship tuples and evaluates permissions.
    """
    def __init__(self):
        # Set of tuples: (resource_type, resource_id, relation, subject_type, subject_id)
        self.relationships: Set[Tuple[str, str, str, str, str]] = set()
        logger.info("Initializing in-memory SpiceDB Simulator.")

    def write_relationships(self, tuples: List[Tuple[str, str, str, str, str]]) -> None:
        for t in tuples:
            self.relationships.add(t)
            logger.info(f"Mock SpiceDB: Written relationship -> {t[0]}:{t[1]}#{t[2]}@{t[3]}:{t[4]}")

    def delete_relationships(self, resource_type: str, resource_id: str = None) -> None:
        """
        Deletes relationships matching the resource type and optional resource ID.
        """
        before_count = len(self.relationships)
        if resource_id:
            # Delete direct document relationships and also chunks that have this document as parent_document
            self.relationships = {
                t for t in self.relationships 
                if not (t[0] == resource_type and t[1] == resource_id) and 
                   not (t[0] == "chunk" and t[2] == "parent_document" and t[3] == resource_type and t[4] == resource_id)
            }
        else:
            self.relationships = {t for t in self.relationships if t[0] != resource_type}
        logger.info(f"Mock SpiceDB: Deleted {before_count - len(self.relationships)} relationships for {resource_type}:{resource_id}.")

    def check_permission(self, resource_type: str, resource_id: str, permission: str, subject_type: str, subject_id: str) -> bool:
        """
        Simulates Zanzibar relationship traversal based on the defined schema.
        """
        # Admin bypass for testing / simple UX
        if subject_type == "user" and subject_id == "admin":
            return True

        if resource_type == "document":
            # permission 'view' = viewer + editor + owner
            # permission 'edit' = editor + owner
            allowed_relations = {"owner"}
            if permission == "view":
                allowed_relations.update({"viewer", "editor"})
            elif permission == "edit":
                allowed_relations.add("editor")

            for rel in allowed_relations:
                # Check for direct relationship
                if (resource_type, resource_id, rel, subject_type, subject_id) in self.relationships:
                    return True
            return False

        elif resource_type == "chunk":
            # permission 'view' = parent_document->view
            if permission == "view":
                # Find the parent documents of this chunk
                parents = [
                    t[4] for t in self.relationships 
                    if t[0] == "chunk" and t[1] == resource_id and t[2] == "parent_document" and t[3] == "document"
                ]
                # Check view permission on any parent document
                for doc_id in parents:
                    if self.check_permission("document", doc_id, "view", subject_type, subject_id):
                        return True
            return False

        return False

    def lookup_resources(self, resource_type: str, permission: str, subject_type: str, subject_id: str) -> List[str]:
        """
        Finds all resource IDs of resource_type that the subject has permission on.
        """
        # Find all unique resource IDs of resource_type in relationships
        all_ids = {t[1] for t in self.relationships if t[0] == resource_type}
        # Special case: also find resources mentioned as subject targets (e.g. chunks parent documents)
        if resource_type == "document":
            all_ids.update({t[4] for t in self.relationships if t[3] == "document"})
            
        allowed_ids = []
        for r_id in all_ids:
            if self.check_permission(resource_type, r_id, permission, subject_type, subject_id):
                allowed_ids.append(r_id)
        return allowed_ids


class RealSpiceDBClient:
    """
    Wrapper for the real SpiceDB client communicating over gRPC.
    """
    def __init__(self, endpoint: str, preshared_key: str):
        self.client = Client(endpoint, insecure_bearer_token_credentials(preshared_key))
        logger.info(f"Initializing connection to SpiceDB at {endpoint}.")
        self.ensure_schema()

    def ensure_schema(self) -> None:
        schema_text = """
        definition user {}

        definition document {
            relation viewer: user
            relation editor: user
            relation owner: user

            permission view = viewer + editor + owner
            permission edit = editor + owner
        }

        definition chunk {
            relation parent_document: document
            permission view = parent_document->view
        }
        """
        try:
            self.client.WriteSchema(WriteSchemaRequest(schema=schema_text))
            logger.info("SpiceDB: Schema verified/written successfully on live server.")
        except Exception as e:
            logger.error(f"Failed to write schema to SpiceDB: {e}")


    def write_relationships(self, tuples: List[Tuple[str, str, str, str, str]]) -> None:
        updates = []
        for r_type, r_id, rel, s_type, s_id in tuples:
            relationship = Relationship(
                resource=ObjectReference(object_type=r_type, object_id=r_id),
                relation=rel,
                subject=SubjectReference(
                    object=ObjectReference(object_type=s_type, object_id=s_id)
                )
            )
            updates.append(
                RelationshipUpdate(
                    operation=RelationshipUpdate.Operation.OPERATION_CREATE,
                    relationship=relationship
                )
            )
        try:
            self.client.WriteRelationships(WriteRelationshipsRequest(updates=updates))
            logger.info(f"Successfully wrote {len(tuples)} relationships to SpiceDB.")
        except Exception as e:
            logger.error(f"Failed to write relationships to SpiceDB: {e}")
            raise e

    def delete_relationships(self, resource_type: str, resource_id: str = None) -> None:
        """
        Deletes relationships matching the resource type and optional resource ID.
        """
        try:
            # Delete document direct relationships
            f = RelationshipFilter(
                resource_type=resource_type,
                optional_resource_id=resource_id
            )
            self.client.DeleteRelationships(DeleteRelationshipsRequest(relationship_filter=f))
            
            # If deleting a document, also clean up chunk parent relationships pointing to it
            if resource_type == "document" and resource_id:
                chunk_filter = RelationshipFilter(
                    resource_type="chunk",
                    optional_relation="parent_document",
                    optional_subject_filter=SubjectFilter(
                        subject_type="document",
                        optional_subject_id=resource_id
                    )
                )
                self.client.DeleteRelationships(DeleteRelationshipsRequest(relationship_filter=chunk_filter))
                
            logger.info(f"Successfully deleted relationships matching {resource_type}:{resource_id} in SpiceDB.")
        except Exception as e:
            logger.error(f"Failed to delete relationships: {e}")
            raise e

    def check_permission(self, resource_type: str, resource_id: str, permission: str, subject_type: str, subject_id: str) -> bool:
        # Admin bypass for quick testing/admin operations
        if subject_type == "user" and subject_id == "admin":
            return True

        try:
            resp = self.client.CheckPermission(
                CheckPermissionRequest(
                    resource=ObjectReference(object_type=resource_type, object_id=resource_id),
                    permission=permission,
                    subject=SubjectReference(
                        object=ObjectReference(object_type=subject_type, object_id=subject_id)
                    ),
                    consistency=Consistency(fully_consistent=True)
                )
            )
            return resp.permissionship == CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
        except Exception as e:
            logger.error(f"Failed to check permission in SpiceDB: {e}")
            return False

    def lookup_resources(self, resource_type: str, permission: str, subject_type: str, subject_id: str) -> List[str]:
        try:
            request = LookupResourcesRequest(
                resource_object_type=resource_type,
                permission=permission,
                subject=SubjectReference(
                    object=ObjectReference(object_type=subject_type, object_id=subject_id)
                ),
                consistency=Consistency(fully_consistent=True)
            )
            allowed_ids = []
            for resp in self.client.LookupResources(request):
                allowed_ids.append(resp.resource_object_id)
            return allowed_ids
        except Exception as e:
            logger.error(f"Failed to lookup resources in SpiceDB: {e}")
            return []


# Global client instance
_spicedb_client = None

def get_spicedb_client():
    """
    Returns the configured SpiceDB client.
    First checks if authzed is installed and env variables are present.
    If yes, returns the gRPC client. If no, or if connection fails, returns the in-memory simulator.
    """
    global _spicedb_client
    if _spicedb_client is not None:
        return _spicedb_client

    endpoint = os.getenv("SPICEDB_ENDPOINT")
    preshared_key = os.getenv("SPICEDB_PRESHARED_KEY")

    if HAS_AUTHZED and endpoint and preshared_key:
        try:
            _spicedb_client = RealSpiceDBClient(endpoint, preshared_key)
            logger.info("SpiceDB: Connected to live instance successfully.")
            return _spicedb_client
        except Exception as e:
            logger.error(f"SpiceDB: Failed to connect to live instance ({e}). Falling back to simulator.")
    
    # Fallback to simulator
    _spicedb_client = SpiceDBSimulator()
    return _spicedb_client
