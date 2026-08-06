import os
from llama_index.readers.file import PDFReader
from llama_index.core.node_parser import SentenceSplitter
from dotenv import load_dotenv
import sys
import re
import json


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import add_documents, get_client
from database.spicedb_client import get_spicedb_client

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


_analyzer = None
_anonymizer = None


def _register_custom_recognizers(analyzer):
    """
    Registers custom recognizers configured from the .env environment variables.
    """
    from presidio_analyzer import PatternRecognizer, Pattern
    
    # 1. Custom Deny List
    custom_deny_list_str = os.getenv("PRESIDIO_CUSTOM_DENY_LIST")
    if custom_deny_list_str:
        # Split by comma, strip whitespace, and filter out empty strings
        deny_list = [item.strip() for item in custom_deny_list_str.split(",") if item.strip()]
        if deny_list:
            print(f"Registering custom Presidio deny list with terms: {deny_list}")
            deny_list_recognizer = PatternRecognizer(
                supported_entity="CUSTOM_DENY_LIST",
                deny_list=deny_list,
                deny_list_score=1.0
            )
            analyzer.registry.add_recognizer(deny_list_recognizer)
            
    # 2. Custom Regex/Pattern Recognizers (JSON)
    custom_patterns_json = os.getenv("PRESIDIO_CUSTOM_PATTERNS")
    if custom_patterns_json:
        try:
            patterns_data = json.loads(custom_patterns_json)
            if not isinstance(patterns_data, list):
                print("Error: PRESIDIO_CUSTOM_PATTERNS should be a JSON array/list.")
                patterns_data = []
            
            for item in patterns_data:
                entity = item.get("entity")
                regex_str = item.get("regex")
                if not entity or not regex_str:
                    print(f"Skipping invalid custom pattern configuration: {item}")
                    continue
                    
                score = float(item.get("score", 0.85))
                context = item.get("context", None)
                
                print(f"Registering custom Presidio regex recognizer for entity '{entity}': {regex_str}")
                pattern = Pattern(
                    name=f"{entity.lower()}_pattern",
                    regex=regex_str,
                    score=score
                )
                
                recognizer = PatternRecognizer(
                    supported_entity=entity,
                    patterns=[pattern],
                    context=context
                )
                analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            print(f"Error parsing PRESIDIO_CUSTOM_PATTERNS: {e}")


def get_analyzer_and_anonymizer():
    """
    Lazily initializes and returns the Presidio Analyzer and Anonymizer engines.
    """
    global _analyzer, _anonymizer
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
            
            # Configure NLP engine to use en_core_web_sm
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            })
            nlp_engine = provider.create_engine()
            
            _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            _anonymizer = AnonymizerEngine()
            
            # Register custom recognizers configured from environment variables
            _register_custom_recognizers(_analyzer)

        except Exception as e:
            print(f"Error initializing Presidio engines: {e}")
            print("Please ensure you have downloaded the required spaCy model (e.g., run `python -m spacy download en_core_web_sm`).")
            raise e
    return _analyzer, _anonymizer


def load_and_chunk_pdf(path: str):
    docs = PDFReader().load_data(file=path)
    texts = [d.text for d in docs if getattr(d, "text", None)]
    
    analyzer, anonymizer = get_analyzer_and_anonymizer()
    
    anonymized_texts = []
    for t in texts:
        if not t.strip():
            anonymized_texts.append(t)
            continue
        results = analyzer.analyze(text=t, language="en")
        redacted = anonymizer.anonymize(text=t, analyzer_results=results)
        anonymized_texts.append(redacted.text)
        
    chunks = []
    for t in anonymized_texts:
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


def store_embeddings(chunks, embeddings, file_path, owner_id: str = "admin", viewers: list[str] = None):
    """
    Automatically extracts the filename, sanitizes it, and uses it
    as the ChromaDB collection name to store the chunks and embeddings.
    Also registers relationships in SpiceDB for user-based filtering.
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

    # Create metadatas and ids with unique chunk/doc parameters
    ids = []
    metadatas = []
    tuples_to_write = []
    
    # 1. Document relationship tuples
    # Owner relationship
    tuples_to_write.append(("document", collection_name, "owner", "user", owner_id))
    # Viewer relationships
    if viewers:
        for viewer in viewers:
            if viewer.strip() and viewer.strip() != owner_id:
                tuples_to_write.append(("document", collection_name, "viewer", "user", viewer.strip()))

    for i, chunk in enumerate(chunks):
        chunk_id = f"{collection_name}_chunk_{i}"
        ids.append(chunk_id)
        
        # Add document_id and chunk_id to metadata for pre/post filtering queries
        metadatas.append({
            "document_id": collection_name,
            "chunk_id": chunk_id,
            "source": file_path
        })
        
        # 2. Chunk relationships (parent_document points to document)
        tuples_to_write.append(("chunk", chunk_id, "parent_document", "document", collection_name))

    print(f"Storing {len(chunks)} chunks in ChromaDB collection: '{collection_name}'")
    add_documents(
        collection_name=collection_name, 
        texts=chunks, 
        embeddings=embeddings, 
        metadatas=metadatas, 
        ids=ids
    )

    print("Registering permissions and relationships in SpiceDB...")
    spicedb = get_spicedb_client()
    try:
        # Delete existing relationships for this document in SpiceDB to guarantee a clean reload
        spicedb.delete_relationships("document", collection_name)
        
        # Write relationships to SpiceDB
        spicedb.write_relationships(tuples_to_write)
        print(f"Registered document '{collection_name}' permissions in SpiceDB (Owner: '{owner_id}', Viewers: {viewers or []}).")
    except Exception as e:
        print(f"Warning: Failed to write permissions to SpiceDB: {e}")

    return collection_name