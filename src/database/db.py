import os
import chromadb
from typing import List, Dict, Any

# Define a local storage directory for ChromaDB
DB_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "chroma_db"
)

_client = None


def get_client() -> chromadb.PersistentClient:
    """
    Initializes and returns a thread-safe persistent ChromaDB client.
    """
    global _client
    if _client is None:
        os.makedirs(DB_DIR, exist_ok=True)
        _client = chromadb.PersistentClient(path=DB_DIR)
    return _client


def get_or_create_collection(collection_name: str):
    """
    Gets or creates a collection in the Chroma database.
    """
    client = get_client()
    return client.get_or_create_collection(name=collection_name)


def add_documents(
    collection_name: str,
    texts: List[str],
    embeddings: List[List[float]],
    metadatas: List[Dict[str, Any]] = None,
    ids: List[str] = None
) -> None:
    """
    Adds document text chunks along with their pre-computed embeddings to ChromaDB.
    """
    if not texts:
        return

    collection = get_or_create_collection(collection_name)
    
    # Generate sequential unique IDs if not provided
    if ids is None:
        start_id = collection.count()
        ids = [f"doc_{start_id + i}" for i in range(len(texts))]

    # Ensure metadatas exist and do not contain empty dicts (ChromaDB rejects empty dicts)
    if metadatas is None:
        metadatas = [{"source": "unknown"} for _ in range(len(texts))]
    else:
        metadatas = [m if m else {"source": "unknown"} for m in metadatas]

    collection.add(
        documents=texts,
        embeddings=embeddings,
        metadatas=metadatas,
        ids=ids
    )


def query_documents(
    collection_name: str,
    query_embedding: List[float],
    n_results: int = 5,
    where: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Queries ChromaDB using a pre-computed query embedding with optional metadata filtering.
    Returns matched documents, metadata, and distances.
    """
    collection = get_or_create_collection(collection_name)
    
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        where=where
    )
    return results


def get_all_documents(collection_name: str, include: List[str] = None) -> Dict[str, Any]:
    """
    Retrieves all stored items (documents, metadatas, IDs) from the collection.
    By default, returns everything.
    """
    collection = get_or_create_collection(collection_name)
    # include defaults to ['documents', 'metadatas']
    if include is None:
        include = ["documents", "metadatas"]
    return collection.get(include=include)


def get_collection_count(collection_name: str) -> int:
    """
    Returns the total number of items stored in the collection.
    """
    collection = get_or_create_collection(collection_name)
    return collection.count()
