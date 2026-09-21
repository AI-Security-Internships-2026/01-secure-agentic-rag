import pytest

from secure_rag.agent.graph import query_rag_system, retrieve_authorized
from secure_rag.authz.client import get_authz_client, reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


def setup_function():
    reset_vector_store()
    reset_authz_client()
    ingest_texts(
        "test_spicedb_doc",
        [
            "Secret password to the server is: 12345-cyber-secure.",
            "Normal public notice: Scannable assets are listed in annex A.",
        ],
        owner_id="alice",
        tenant_id="finance",
        viewers=["bob"],
        redact_pii=False,
    )


def test_simulator_permissions():
    authz = get_authz_client()
    assert authz.check_permission("document", "test_spicedb_doc", "view", "user", "alice")
    assert authz.check_permission("document", "test_spicedb_doc", "view", "user", "bob")
    assert not authz.check_permission("document", "test_spicedb_doc", "view", "user", "eve")


def test_prefilter_denies_unrelated_user():
    chunks, diag = retrieve_authorized(
        "password",
        "eve",
        filtering_mode="pre",
        collection_name="test_spicedb_doc",
        tenant_id="hr",
    )
    assert chunks == []
    assert "test_spicedb_doc" not in diag.get("allowed_documents", ["test_spicedb_doc"])


# --- Issue S2 Regression Test Matrix (Option A strict per-doc ACL) ---


@pytest.mark.parametrize(
    "user,doc,expected",
    [
        ("tenant_member_charlie", "eng_doc_1", False),
        ("tenant_member_charlie", "eng_doc_2", False),
        ("tenant_member_dave", "eng_doc_1", False),
        ("tenant_member_dave", "eng_doc_2", False),
    ],
)
def test_tenant_member_without_doc_grant_cannot_view(user, doc, expected):
    """4 cases: Tenant member without explicit document grant CANNOT view documents in tenant."""
    reset_vector_store()
    reset_authz_client()
    authz = get_authz_client()

    ingest_texts("eng_doc_1", ["Engineering Doc 1 Content"], owner_id="alice", tenant_id="engineering", redact_pii=False)
    ingest_texts("eng_doc_2", ["Engineering Doc 2 Content"], owner_id="alice", tenant_id="engineering", redact_pii=False)

    # Charlie and Dave are members of tenant "engineering", but not granted on docs
    authz.write_relationships(
        [
            ("tenant", "engineering", "member", "user", "tenant_member_charlie"),
            ("tenant", "engineering", "member", "user", "tenant_member_dave"),
        ]
    )

    assert authz.check_permission("document", doc, "view", "user", user) is expected


@pytest.mark.parametrize(
    "user,doc,expected",
    [
        ("bob_viewer_doc1", "eng_doc_1", True),
        ("bob_viewer_doc1", "eng_doc_2", False),
        ("carol_viewer_doc2", "eng_doc_1", False),
        ("carol_viewer_doc2", "eng_doc_2", True),
    ],
)
def test_doc_viewer_isolation_same_tenant(user, doc, expected):
    """4 cases: Viewer on doc1 only can view doc1, CANNOT view doc2 even within same tenant."""
    reset_vector_store()
    reset_authz_client()
    authz = get_authz_client()

    ingest_texts(
        "eng_doc_1",
        ["Engineering Doc 1"],
        owner_id="alice",
        tenant_id="engineering",
        viewers=["bob_viewer_doc1"],
        redact_pii=False,
    )
    ingest_texts(
        "eng_doc_2",
        ["Engineering Doc 2"],
        owner_id="alice",
        tenant_id="engineering",
        viewers=["carol_viewer_doc2"],
        redact_pii=False,
    )

    assert authz.check_permission("document", doc, "view", "user", user) is expected


def test_owner_and_editor_grants():
    """4 cases: Owner / Editor grants work properly for view and edit."""
    reset_vector_store()
    reset_authz_client()
    authz = get_authz_client()

    ingest_texts("doc_rbac", ["RBAC content"], owner_id="owner_user", tenant_id="engineering", redact_pii=False)
    authz.write_relationships(
        [
            ("document", "doc_rbac", "editor", "user", "editor_user"),
            ("document", "doc_rbac", "viewer", "user", "viewer_user"),
        ]
    )

    # 1. Owner can view and edit
    assert authz.check_permission("document", "doc_rbac", "view", "user", "owner_user") is True
    assert authz.check_permission("document", "doc_rbac", "edit", "user", "owner_user") is True

    # 2. Editor can view and edit
    assert authz.check_permission("document", "doc_rbac", "view", "user", "editor_user") is True
    assert authz.check_permission("document", "doc_rbac", "edit", "user", "editor_user") is True

    # 3. Viewer can view but CANNOT edit
    assert authz.check_permission("document", "doc_rbac", "view", "user", "viewer_user") is True
    assert authz.check_permission("document", "doc_rbac", "edit", "user", "viewer_user") is False

    # 4. Unrelated user cannot view or edit
    assert authz.check_permission("document", "doc_rbac", "view", "user", "random_user") is False
    assert authz.check_permission("document", "doc_rbac", "edit", "user", "random_user") is False


def test_cross_tenant_viewer_grants_disjoint():
    """4 cases: Cross-tenant isolation and explicit per-doc cross-tenant grants."""
    reset_vector_store()
    reset_authz_client()
    authz = get_authz_client()

    ingest_texts("eng_doc_a", ["Engineering Doc A"], owner_id="alice", tenant_id="engineering", redact_pii=False)
    ingest_texts("eng_doc_b", ["Engineering Doc B"], owner_id="alice", tenant_id="engineering", redact_pii=False)
    ingest_texts("fin_doc_a", ["Finance Doc A"], owner_id="frank", tenant_id="finance", redact_pii=False)

    # External user from finance is granted viewer on eng_doc_a ONLY
    authz.write_relationships([("document", "eng_doc_a", "viewer", "user", "frank")])

    # 1. Frank can view eng_doc_a
    assert authz.check_permission("document", "eng_doc_a", "view", "user", "frank") is True
    # 2. Frank CANNOT view eng_doc_b in engineering
    assert authz.check_permission("document", "eng_doc_b", "view", "user", "frank") is False
    # 3. Frank is NOT tenant member of engineering
    assert authz.check_permission("tenant", "engineering", "view", "user", "frank") is False
    # 4. Alice CANNOT view fin_doc_a
    assert authz.check_permission("document", "fin_doc_a", "view", "user", "alice") is False


# Complete 20-case explicit matrix
PERMISSION_MATRIX_CASES = [
    # (subject_id, subject_tenant, resource_doc, expected_allowed)
    # Tenant members without doc grant (cases 1-4)
    ("tenant_member_1", "engineering", "eng_doc_alpha", False),
    ("tenant_member_1", "engineering", "eng_doc_beta", False),
    ("tenant_member_2", "engineering", "eng_doc_alpha", False),
    ("tenant_member_2", "engineering", "eng_doc_beta", False),
    # Viewer on doc_alpha only (cases 5-8)
    ("viewer_alpha_only", "engineering", "eng_doc_alpha", True),
    ("viewer_alpha_only", "engineering", "eng_doc_beta", False),
    ("viewer_beta_only", "engineering", "eng_doc_alpha", False),
    ("viewer_beta_only", "engineering", "eng_doc_beta", True),
    # Owners on their respective docs (cases 9-12)
    ("owner_alpha", "engineering", "eng_doc_alpha", True),
    ("owner_alpha", "engineering", "eng_doc_beta", False),
    ("owner_beta", "engineering", "eng_doc_alpha", False),
    ("owner_beta", "engineering", "eng_doc_beta", True),
    # Editors on their respective docs (cases 13-16)
    ("editor_alpha", "engineering", "eng_doc_alpha", True),
    ("editor_alpha", "engineering", "eng_doc_beta", False),
    ("editor_beta", "engineering", "eng_doc_alpha", False),
    ("editor_beta", "engineering", "eng_doc_beta", True),
    # Cross-tenant users with and without explicit grant (cases 17-20)
    ("external_guest", "marketing", "eng_doc_alpha", True),  # explicitly granted viewer
    ("external_guest", "marketing", "eng_doc_beta", False),  # NOT granted
    ("foreign_user", "marketing", "eng_doc_alpha", False),  # no grant at all
    ("foreign_user", "marketing", "eng_doc_beta", False),  # no grant at all
]


@pytest.mark.parametrize("user,user_tenant,doc,expected", PERMISSION_MATRIX_CASES)
def test_permission_matrix_20_cases(user, user_tenant, doc, expected):
    reset_vector_store()
    reset_authz_client()
    authz = get_authz_client()

    ingest_texts("eng_doc_alpha", ["Alpha Confidential"], owner_id="owner_alpha", tenant_id="engineering", redact_pii=False)
    ingest_texts("eng_doc_beta", ["Beta Confidential"], owner_id="owner_beta", tenant_id="engineering", redact_pii=False)

    # Set up specific roles
    authz.write_relationships(
        [
            ("tenant", "engineering", "member", "user", "tenant_member_1"),
            ("tenant", "engineering", "member", "user", "tenant_member_2"),
            ("document", "eng_doc_alpha", "viewer", "user", "viewer_alpha_only"),
            ("document", "eng_doc_beta", "viewer", "user", "viewer_beta_only"),
            ("document", "eng_doc_alpha", "editor", "user", "editor_alpha"),
            ("document", "eng_doc_beta", "editor", "user", "editor_beta"),
            ("tenant", "marketing", "member", "user", "external_guest"),
            ("document", "eng_doc_alpha", "viewer", "user", "external_guest"),
            ("tenant", "marketing", "member", "user", "foreign_user"),
        ]
    )

    assert authz.check_permission("document", doc, "view", "user", user) is expected
    # Verify chunk-level inheritance
    assert authz.check_permission("chunk", f"{doc}__0", "view", "user", user) is expected


def test_cross_doc_query_isolation_integration():
    """Integration pipeline test: Ingest 2 docs in same tenant, query as viewer-of-doc1-only."""
    reset_vector_store()
    reset_authz_client()

    ingest_texts(
        "incident_report_17",
        ["Public incident report on server outage. CANARY_INCIDENT_17"],
        owner_id="ciso",
        tenant_id="engineering",
        viewers=["bob"],
        redact_pii=False,
    )
    ingest_texts(
        "threat_intel_42",
        ["Top secret malware threat intelligence. CANARY_MALWARE_42"],
        owner_id="ciso",
        tenant_id="engineering",
        viewers=[],  # Bob is NOT a viewer
        redact_pii=False,
    )

    result = query_rag_system(
        collection_name="",
        query="threat intelligence and server outage CANARY_MALWARE_42",
        user_id="bob",
        tenant_id="engineering",
        filtering_mode="pre",
        enable_indirect_injection_scan=False,
        enable_agent_loop=False,
    )

    retrieved_docs = {item["document_id"] for item in result.get("retrieved", [])}
    assert "incident_report_17" in retrieved_docs
    assert "threat_intel_42" not in retrieved_docs
    assert "CANARY_MALWARE_42" not in result["answer"]

