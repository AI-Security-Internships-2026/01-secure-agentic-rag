import os
import google.generativeai as genai
from llama_index.readers.file import PDFReader
from llama_index.core.node_parser import SentenceSplitter
from dotenv import load_dotenv
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import add_documents

load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

EMBED_MODEL = os.getenv("EMBED_MODEL", "models/gemini-embedding-001")
EMBED_DIM = 768  # Gemini embedding dimension (important!)

splitter = SentenceSplitter(chunk_size=1000, chunk_overlap=200)


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


def load_and_chunk_pdf(path: str):
    docs = PDFReader().load_data(file=path)
    texts = [d.text for d in docs if getattr(d, "text", None)]
    chunks = []
    for t in texts:
        chunks.extend(splitter.split_text(t))
    return chunks


def embed_texts(texts: list[str]) -> list[list[float]]:
    embeddings = []

    for text in texts:
        response = genai.embed_content(
            model=RESOLVED_EMBED_MODEL,
            content=text,
            task_type="retrieval_document",  # important for RAG
            output_dimensionality=EMBED_DIM,
        )
        embeddings.append(response["embedding"])
    return embeddings


import re

def store_embeddings(chunks, embeddings, file_path):
    """
    Automatically extracts the filename, sanitizes it, and uses it
    as the ChromaDB collection name to store the chunks and embeddings.
    """
    # Extract filename without directory and extension
    base_name = os.path.basename(file_path)
    name_without_ext = os.path.splitext(base_name)[0]
    
    # Sanitize the name for ChromaDB requirements (lowercase, 3-63 chars, alphanumeric/underscore/hyphen)
    collection_name = name_without_ext.lower().strip()
    collection_name = re.sub(r'[^a-z0-9_-]', '_', collection_name)
    collection_name = re.sub(r'_+', '_', collection_name).strip('_')
    
    # Fallback if the name is too short
    if len(collection_name) < 3:
        collection_name = f"col_{collection_name}"
        
    collection_name = collection_name[:63]
    
    print(f"Storing in ChromaDB collection: '{collection_name}'")
    add_documents(collection_name=collection_name, texts=chunks, embeddings=embeddings)

    
if __name__ == "__main__":
    test_pdf = "../../datasets/system design.pdf"
    if os.path.exists(test_pdf):
        print(f"Loading and chunking PDF: {test_pdf}")
        chunks = load_and_chunk_pdf(test_pdf)
        print(f"Created {len(chunks)} chunks.")
        if chunks:
            print("Embedding first chunk...")
            embeddings = embed_texts([chunks[0]])
            print(f"Embedding vector dimension: {len(embeddings[0])}")
            # Test storing the single embedded chunk using the automatic filename extraction
            store_embeddings([chunks[0]], embeddings, test_pdf)
    else:
        print("Set a valid PDF file path to run test.")
