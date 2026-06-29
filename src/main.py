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
from database.db import get_collection_count
from data_functions.query_engine import query_rag_system

load_dotenv()

PROJECT_NAME = "Secure Agentic RAG for Cybersecurity Knowledge Bases"
ORGANISATION = "CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna"
STATUS = "Interactive Query Interface — Active"
DEFAULT_COLLECTION = "system_design"


def ensure_default_document() -> None:
    """
    Checks if the default document is indexed in ChromaDB.
    If not, it indexes 'datasets/system design.pdf'.
    """
    try:
        count = get_collection_count(DEFAULT_COLLECTION)
    except Exception:
        count = 0

    if count > 0 and count < 10:
        print(f"\nWarning: Collection '{DEFAULT_COLLECTION}' only contains {count} chunks.")
        print("This likely indicates an incomplete database load (e.g., copyright page only).")
        reindex = input("Would you like to clear and re-index the PDF document? (y/n): ").strip().lower()
        if reindex == 'y':
            count = 0

    if count == 0:
        print(f"Collection '{DEFAULT_COLLECTION}' is empty or does not exist.")
        # Find the default PDF path relative to this script
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf_path = os.path.join(base_dir, "datasets", "system design.pdf")

        
        if os.path.exists(pdf_path):
            print(f"Automatically indexing default document: {pdf_path}")
            chunks = load_and_chunk_pdf(pdf_path)
            print(f"Created {len(chunks)} chunks from PDF.")
            if chunks:
                print("Generating embeddings using Gemini API...")
                embeddings = embed_texts(chunks)
                print(f"Storing {len(embeddings)} embeddings in ChromaDB...")
                store_embeddings(chunks, embeddings, pdf_path)
                print("Default document successfully indexed!")
        else:
            print(f"Warning: Default PDF not found at {pdf_path}. Please index a document first.")
    else:
        print(f"Using existing ChromaDB collection: '{DEFAULT_COLLECTION}' ({count} chunks loaded).")


def main() -> None:
    print("=" * 60)
    print(f"Project : {PROJECT_NAME}")
    print(f"Org     : {ORGANISATION}")
    print(f"Status  : {STATUS}")
    print("=" * 60)
    print()

    # Ensure default dataset is loaded
    ensure_default_document()
    print()
    print("Ready to answer questions from the document.")
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
                
            print("Searching and generating answer...")
            result = query_rag_system(DEFAULT_COLLECTION, query)
            
            print("\nAnswer:")
            print(result["answer"])
            
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

