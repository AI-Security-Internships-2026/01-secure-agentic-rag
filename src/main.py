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


def index_new_pdf(pdf_path: str) -> str:
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
        
        print("Saving embeddings in ChromaDB...")
        collection_name = store_embeddings(chunks, embeddings, pdf_path)
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
            
    print()
    print("=" * 60)
    print("Secure Agentic RAG — Document Selection")
    print("=" * 60)
    
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
                    return selected_col
                elif val == len(col_names) + 1 or (not col_names and val == 1):
                    pdf_path = prompt_for_pdf()
                    if pdf_path:
                        col = index_new_pdf(pdf_path)
                        if col:
                            return col
                else:
                    print(f"Invalid option. Please enter a number between 1 and {len(col_names) + 1 if col_names else 1}.")
            else:
                pdf_path = choice.strip("\"'")
                if os.path.exists(pdf_path) and pdf_path.lower().endswith(".pdf"):
                    col = index_new_pdf(pdf_path)
                    if col:
                        return col
                else:
                    print("Error: The path does not exist or is not a valid PDF file. Please try again.")
        except KeyboardInterrupt:
            print("\nExiting document selection.")
            sys.exit(0)


def main() -> None:
    print("=" * 60)
    print(f"Project : {PROJECT_NAME}")
    print(f"Org     : {ORGANISATION}")
    print(f"Status  : {STATUS}")
    print("=" * 60)

    # Retrieve or index a collection
    collection_name = get_or_upload_collection()
    
    print("\n" + "=" * 60)
    print("Ready to answer questions from the document.")
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
                
            print("Searching and generating answer...")
            result = query_rag_system(collection_name, query)
            
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

