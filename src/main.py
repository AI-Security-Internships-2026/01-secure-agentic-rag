"""
Secure Agentic RAG for Cybersecurity Knowledge Bases
CNIT/PNTLab Pisa — AI Security Internship 2026

Main entry point containing the interactive query interface.
"""

import os
import sys
from dotenv import load_dotenv

# Ensure the parent directory is in the path for proper package imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from data_functions.load_document import load_and_chunk_pdf, embed_texts, store_embeddings
from data_functions.query_engine import query_rag_system

load_dotenv()

PROJECT_NAME = "Secure Agentic RAG for Cybersecurity Knowledge Bases"
ORGANISATION = "CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna"
STATUS = "Interactive Query Interface — Active"

ACTIVE_USER = "admin"
FILTERING_MODE = "pre"


def register_default_permissions(collection_name: str) -> None:
    """
    Registers demo/default relationship tuples for a collection in SpiceDB.
    Sets 'admin' as owner, 'alice' as viewer, and does not register 'bob'.
    Also registers chunk parent relationships if they exist in ChromaDB.
    """
    from database.spicedb_client import get_spicedb_client
    from database.db import get_client
    
    print(f"\nRegistering default simulation permissions in SpiceDB for document '{collection_name}'...")
    spicedb = get_spicedb_client()
    
    # 1. Document relations (admin is owner, alice is viewer, bob is not registered, hence has no access)
    tuples = [
        ("document", collection_name, "owner", "user", "admin"),
        ("document", collection_name, "viewer", "user", "alice")
    ]
    
    # 2. Query chroma to get all chunk IDs and link them
    try:
        chroma_client = get_client()
        collection = chroma_client.get_or_create_collection(collection_name)
        data = collection.get(include=["metadatas"])
        chunk_ids = data.get("ids", [])
        for cid in chunk_ids:
            tuples.append(("chunk", cid, "parent_document", "document", collection_name))
    except Exception as e:
        print(f"Warning: Could not fetch chunks from Chroma to link parent document: {e}")
        
    try:
        spicedb.delete_relationships("document", collection_name)
        spicedb.write_relationships(tuples)
        print(f"Default SpiceDB permissions registered for '{collection_name}':")
        print(f"  - Owner: admin")
        print(f"  - Viewer: alice")
        print(f"  - No Access: bob (or any other user)")
    except Exception as e:
        print(f"Warning: Failed to write default permissions: {e}")


def prompt_for_pdf() -> str:
    """
    Repeatedly prompts the user for a valid PDF path until one is entered or 'cancel' is typed.
    """
    while True:
        pdf_path = input("\nEnter the path to your PDF document (or type 'cancel' to go back): ").strip().strip("\"'")
        if pdf_path.lower() == 'cancel':
            return ""
        if os.path.exists(pdf_path) and pdf_path.lower().endswith(".pdf"):
            return pdf_path
        else:
            print("Error: The path does not exist or is not a valid PDF file. Please try again.")


def index_new_pdf(pdf_path: str, owner_id: str = "admin") -> str:
    """
    Loads, chunks, generates embeddings using Gemini, and indexes a PDF file.
    Returns the collection name.
    """
    print(f"\nIndexing PDF document: {pdf_path}")
    try:
        chunks = load_and_chunk_pdf(pdf_path)
        print(f"Parsed {len(chunks)} chunks from the PDF.")
        if not chunks:
            print("Error: No text chunks could be extracted from this PDF.")
            return ""
            
        print("Generating embeddings using Gemini API...")
        embeddings = embed_texts(chunks)
        print(f"Generated {len(embeddings)} embeddings.")
        
        # Prompt for document viewers list
        print("\n--- Document Access Control configuration ---")
        viewers_input = input("Enter comma-separated usernames allowed to view this document (e.g. alice, bob): ").strip()
        viewers = [v.strip() for v in viewers_input.split(",") if v.strip()] if viewers_input else []
        
        print("Saving embeddings in ChromaDB...")
        collection_name = store_embeddings(chunks, embeddings, pdf_path, owner_id=owner_id, viewers=viewers)
        print(f"Success! Document successfully indexed under collection '{collection_name}'.")
        return collection_name
    except Exception as e:
        print(f"Error indexing PDF: {e}")
        return ""


def get_or_upload_collection() -> str:
    """
    Prompts the user to select an existing ChromaDB collection or index/upload a new PDF document.
    Returns the active collection name.
    """
    from database.db import get_client
    
    client = get_client()
    try:
        collections = client.list_collections()
    except Exception as e:
        print(f"Error fetching collections from ChromaDB: {e}")
        collections = []
        
    col_names = []
    for col in collections:
        if isinstance(col, str):
            col_names.append(col)
        else:
            col_names.append(col.name)
    
    if col_names:
        print("\nAvailable Indexed Documents:")
        for idx, name in enumerate(col_names, 1):
            print(f"  [{idx}] {name}")
        print(f"  [{len(col_names) + 1}] Index / Upload a new PDF document")
    else:
        print("\nNo indexed documents found.")
        print("You need to index / upload a new PDF document to begin.")
        
    while True:
        try:
            choice = input(f"\nSelect an option (1-{len(col_names) + 1 if col_names else 1}) or enter path to a PDF file: ").strip()
            if not choice:
                continue
                
            if choice.isdigit():
                val = int(choice)
                if col_names and 1 <= val <= len(col_names):
                    selected_col = col_names[val - 1]
                    print(f"\nUsing existing collection: '{selected_col}'")
                    # Permissions are already stored in SpiceDB during upload.
                    return selected_col
                elif val == len(col_names) + 1 or (not col_names and val == 1):
                    pdf_path = prompt_for_pdf()
                    if pdf_path:
                        col = index_new_pdf(pdf_path, owner_id=ACTIVE_USER)
                        if col:
                            return col
                else:
                    print(f"Invalid option. Please enter a number between 1 and {len(col_names) + 1 if col_names else 1}.")
            else:
                pdf_path = choice.strip("\"'")
                if os.path.exists(pdf_path) and pdf_path.lower().endswith(".pdf"):
                    col = index_new_pdf(pdf_path, owner_id=ACTIVE_USER)
                    if col:
                        return col
                else:
                    print("Error: The path does not exist or is not a valid PDF file. Please try again.")
        except KeyboardInterrupt:
            print("\nExiting document selection.")
            sys.exit(0)


def main() -> None:
    global ACTIVE_USER, FILTERING_MODE

    print("\n--- SpiceDB Access Control Setup ---")
    username = input("Enter your username (default: 'admin'): ").strip()
    if username:
        ACTIVE_USER = username
    else:
        ACTIVE_USER = "admin"
    print(f"Active user set to: '{ACTIVE_USER}' (Type \\user to change later)")

    print("\nSelect Access Control Filtering Mode:")
    print("  [1] No security filtering (baseline)")
    print("  [2] Pre-filtering (via SpiceDB LookupResources)")
    print("  [3] Post-filtering (via SpiceDB CheckPermission)")
    mode_choice = input("Select option (1-3, default: 2): ").strip()
    if mode_choice == "1":
        FILTERING_MODE = "none"
    elif mode_choice == "3":
        FILTERING_MODE = "post"
    else:
        FILTERING_MODE = "pre"
    print(f"Access control mode set to: '{FILTERING_MODE.upper()}' (Type \\mode to change later)")

    # Retrieve or index a collection
    collection_name = get_or_upload_collection()
    
    print("\n" + "=" * 60)
    print("Ready to answer questions from the document.")
    print("Type '\\user' to switch active user.")
    print("Type '\\mode' to switch filtering mode.")
    print("Type '\\spicedb' to view registered simulator relationships.")
    print("Type '\\change' to switch documents/collections.")
    print("Type 'exit' or 'quit' to end the session.")
    print("-" * 60)
    
    while True:
        try:
            query = input("\nEnter your query: ").strip()
            if not query:
                continue
            if query.lower() in ("exit", "quit"):
                print("Goodbye!")
                break
            if query.lower() == "\\change":
                collection_name = get_or_upload_collection()
                print("\n" + "=" * 60)
                print("Ready to answer questions from the new document.")
                print("Type '\\change' to switch documents/collections.")
                print("Type 'exit' or 'quit' to end the session.")
                print("-" * 60)
                continue
            if query.lower() == "\\user":
                new_user = input("Enter new username: ").strip()
                if new_user:
                    ACTIVE_USER = new_user
                    print(f"Active user changed to: '{ACTIVE_USER}'")
                continue
            if query.lower() == "\\mode":
                print("\nSelect Access Control Filtering Mode:")
                print("  [1] No security filtering (baseline)")
                print("  [2] Pre-filtering (via SpiceDB LookupResources)")
                print("  [3] Post-filtering (via SpiceDB CheckPermission)")
                mode_choice = input("Select option (1-3): ").strip()
                if mode_choice == "1":
                    FILTERING_MODE = "none"
                elif mode_choice == "3":
                    FILTERING_MODE = "post"
                elif mode_choice == "2":
                    FILTERING_MODE = "pre"
                print(f"Access control mode changed to: '{FILTERING_MODE.upper()}'")
                continue
            if query.lower() in ("\\spicedb", "\\permissions"):
                from database.spicedb_client import get_spicedb_client
                spicedb = get_spicedb_client()
                if hasattr(spicedb, "relationships"):
                    print("\n--- Current Registered SpiceDB Relationships ---")
                    for t in sorted(spicedb.relationships):
                        print(f"  {t[0]}:{t[1]}#{t[2]}@{t[3]}:{t[4]}")
                else:
                    print("\nUsing live SpiceDB instance (relationships cannot be listed directly).")
                continue
                
            print(f"Searching and generating answer (User: '{ACTIVE_USER}', Mode: '{FILTERING_MODE.upper()}') ...")
            result = query_rag_system(
                collection_name=collection_name, 
                query=query, 
                user_id=ACTIVE_USER, 
                filtering_mode=FILTERING_MODE
            )
            
            print("\nAnswer:")
            print(result["answer"])
            
            # Print security diagnostics
            diag = result.get("diagnostics", {})
            print(f"\n[Security Diagnostics — SpiceDB]")
            print(f"  Active User      : {diag.get('user_id')}")
            print(f"  Filtering Mode   : {diag.get('filtering_mode', '').upper()}")
            if diag.get("filtering_mode") == "pre":
                print(f"  Allowed Documents: {diag.get('allowed_documents')}")
            elif diag.get("filtering_mode") == "post":
                print(f"  Candidates Fetch : {diag.get('total_candidates_retrieved')}")
                print(f"  Perm Checks Done : {diag.get('permission_checks_count')}")
                print(f"  Chunks Discarded : {diag.get('discarded_chunks_count')}")

            # Print sources for transparency
            print("\nSources (relevant text chunks retrieved):")
            for i, context in enumerate(result["contexts"]):
                snippet = context.strip().replace("\n", " ")
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                print(f"[{i+1}] {snippet}")
            print("-" * 60)
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError processing query: {e}")
            print("-" * 60)


if __name__ == "__main__":
    main()

