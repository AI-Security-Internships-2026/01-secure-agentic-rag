import os
from llama_index.readers.file import PDFReader
from llama_index.core.node_parser import SentenceSplitter
from dotenv import load_dotenv
import sys
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import add_documents, get_client

load_dotenv()

import google.generativeai as genai

# Configure Gemini API
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

EMBED_MODEL = os.getenv("EMBED_MODEL", "models/gemini-embedding-001")
EMBED_DIM = 768  # Gemini embedding dimension (important!)

def _normalize_model_name(name: str) -> str:
    return name if name.startswith("models/") else f"models/{name}"


def _supports_embedding(model_obj) -> bool:
    methods = getattr(model_obj, "supported_generation_methods", None) or []
    return "embedContent" in methods


def _choose_embedding_model() -> str:
    configured = _normalize_model_name(EMBED_MODEL)
    try:
        models = list(genai.list_models())
    except Exception:
        # If model discovery fails (network/permissions), still try configured model.
        return configured

    available = [m for m in models if _supports_embedding(m)]
    available_names = {getattr(m, "name", "") for m in available}

    if configured in available_names:
        return configured

    # Prefer the latest Gemini embedding model first, then legacy fallbacks.
    for preferred in (
        "models/gemini-embedding-001",
        "models/embedding-001",
        "models/text-embedding-004",
    ):
        if preferred in available_names:
            return preferred

    if available:
        return available[0].name

    return configured


RESOLVED_EMBED_MODEL = _choose_embedding_model()

splitter = SentenceSplitter(chunk_size=1000, chunk_overlap=200)


def load_and_chunk_pdf(path: str):
    docs = PDFReader().load_data(file=path)
    texts = [d.text for d in docs if getattr(d, "text", None)]
    chunks = []
    for t in texts:
        chunks.extend(splitter.split_text(t))
    return chunks


def embed_texts(texts: list[str], batch_size: int = 100) -> list[list[float]]:
    """
    Generates embeddings for a list of texts using the Gemini embedding model in batches.
    Optimized to reduce network roundtrips.
    """
    embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        response = genai.embed_content(
            model=RESOLVED_EMBED_MODEL,
            content=batch,
            task_type="retrieval_document",  # important for RAG
            output_dimensionality=EMBED_DIM,
        )
        embeddings.extend(response["embedding"])
    return embeddings



def get_sanitized_collection_name(file_path: str) -> str:
    """
    Extracts the filename, sanitizes it, and returns it as a valid ChromaDB collection name.
    """
    base_name = os.path.basename(file_path)
    name_without_ext = os.path.splitext(base_name)[0]
    
    # Sanitize the name for ChromaDB requirements (lowercase, 3-63 chars, alphanumeric/underscore/hyphen)
    collection_name = name_without_ext.lower().strip()
    collection_name = re.sub(r'[^a-z0-9_-]', '_', collection_name)
    collection_name = re.sub(r'_+', '_', collection_name).strip('_')
    
    # Fallback if the name is too short
    if len(collection_name) < 3:
        collection_name = f"col_{collection_name}"
        
    return collection_name[:63]


def store_embeddings(chunks, embeddings, file_path):
    """
    Automatically extracts the filename, sanitizes it, and uses it
    as the ChromaDB collection name to store the chunks and embeddings.
    Returns the collection name.
    """
    collection_name = get_sanitized_collection_name(file_path)
    
    # Delete collection if it already exists to guarantee clean reload
    client = get_client()
    try:
        client.delete_collection(name=collection_name)
        print(f"Deleted existing collection '{collection_name}' for clean reload.")
    except Exception:
        pass

    print(f"Storing {len(chunks)} chunks in ChromaDB collection: '{collection_name}'")
    add_documents(collection_name=collection_name, texts=chunks, embeddings=embeddings)
    return collection_name


if __name__ == "__main__":
    # Resolve the PDF path relative to this script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_pdf = os.path.normpath(os.path.join(script_dir, "../../datasets/paper.pdf"))
    
    if os.path.exists(test_pdf):
        print(f"Loading and chunking PDF: {test_pdf}")
        chunks = load_and_chunk_pdf(test_pdf)
        print(f"Created {len(chunks)} chunks.")
        if chunks:
            print("Embedding and storing all chunks in ChromaDB...")
            embeddings = embed_texts(chunks)
            print(f"Total embeddings generated: {len(embeddings)}")
            store_embeddings(chunks, embeddings, test_pdf)
            print("Successfully loaded document into ChromaDB!")
    else:
        print(f"Set a valid PDF file path. File not found at: {test_pdf}")
