import os
import sys
import openai
from dotenv import load_dotenv

# Ensure parent directory is in the path for database imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import query_documents

load_dotenv()

import google.generativeai as genai

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


def retrieve_context(
    collection_name: str, 
    query: str, 
    n_results: int = 5,
    user_id: str = "admin",
    filtering_mode: str = "none"
) -> tuple[list[str], dict]:
    """
    Embeds the query using Gemini embedding API
    and retrieves the top N relevant chunks from ChromaDB,
    applying SpiceDB pre-filtering or post-filtering as requested.
    Returns a tuple of (contexts, diagnostics).
    """
    from data_functions.load_document import RESOLVED_EMBED_MODEL, EMBED_DIM
    from database.spicedb_client import get_spicedb_client
    
    spicedb = get_spicedb_client()
    diagnostics = {
        "user_id": user_id,
        "filtering_mode": filtering_mode,
        "allowed_documents": [],
        "total_candidates_retrieved": 0,
        "discarded_chunks_count": 0,
        "permission_checks_count": 0,
    }
    
    # 1. Handle PRE-FILTERING
    if filtering_mode == "pre":
        allowed_docs = spicedb.lookup_resources("document", "view", "user", user_id)
        diagnostics["allowed_documents"] = allowed_docs
        
        # If the requested collection/document is not in the allowed list, deny immediately
        if collection_name not in allowed_docs:
            print(f"\n[Security Check] Pre-filtering: User '{user_id}' is DENIED access to document '{collection_name}'. Returning 0 chunks.")
            return [], diagnostics
            
        where_filter = {"document_id": collection_name}
    else:
        where_filter = None

    # Embed the query
    response = genai.embed_content(
        model=RESOLVED_EMBED_MODEL,
        content=query,
        task_type="retrieval_query",
        output_dimensionality=EMBED_DIM,
    )
    query_embedding = response["embedding"]
        
    # 2. Query ChromaDB
    # If post-filtering, we retrieve a larger candidate pool
    fetch_k = n_results * 4 if filtering_mode == "post" else n_results
    
    results = query_documents(collection_name, query_embedding, n_results=fetch_k, where=where_filter)
    
    # Extract documents and metadata
    documents = results.get("documents", [])
    metadatas = results.get("metadatas", [])
    ids = results.get("ids", [])
    
    # Chroma returns lists of lists. Flatten if necessary
    flat_docs = documents[0] if documents and isinstance(documents[0], list) else documents
    flat_metas = metadatas[0] if metadatas and isinstance(metadatas[0], list) else [None] * len(flat_docs)
    flat_ids = ids[0] if ids and isinstance(ids[0], list) else [None] * len(flat_docs)
    
    diagnostics["total_candidates_retrieved"] = len(flat_docs)
    
    # 3. Handle POST-FILTERING
    if filtering_mode == "post":
        authorized_chunks = []
        for doc_text, meta, chunk_id in zip(flat_docs, flat_metas, flat_ids):
            diagnostics["permission_checks_count"] += 1
            
            # Check permissions on the chunk (falls back to doc if chunk_id is missing)
            has_access = False
            if chunk_id:
                has_access = spicedb.check_permission("chunk", chunk_id, "view", "user", user_id)
            else:
                doc_id = meta.get("document_id", collection_name) if meta else collection_name
                has_access = spicedb.check_permission("document", doc_id, "view", "user", user_id)
                
            if has_access:
                authorized_chunks.append(doc_text)
                if len(authorized_chunks) == n_results:
                    break
            else:
                diagnostics["discarded_chunks_count"] += 1
                
        return authorized_chunks, diagnostics

    # 4. Handle NONE or PRE-FILTERED
    # Pre-filtering already filtered the results, so return the retrieved ones directly
    return flat_docs, diagnostics



def answer_query(query: str, contexts: list[str]) -> str:
    """
    Generates an answer using the retrieved contexts and Groq's API.
    """
    if not contexts:
        return "No relevant context found in the database to answer this question."
        
    # Format contexts into context_text
    context_text = "\n\n".join([f"--- Chunk {i+1} ---\n{c}" for i, c in enumerate(contexts)])
    
    system_prompt = (
        "You are a helpful assistant. Answer the user's question using ONLY the provided "
        "context retrieved from the source document. If the answer cannot be found or inferred "
        "from the context, state that you do not know the answer based on the context."
    )

    user_content = f"Context:\n{context_text}\n\nUser Question: {query}"

    # Initialize OpenAI-compatible client for Groq
    groq_key = os.getenv("GROQ_API_KEY")
    client = openai.OpenAI(
        api_key=groq_key,
        base_url="https://api.groq.com/openai/v1"
    )
    
    model_name = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    
    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]
    )
    
    return response.choices[0].message.content


def query_rag_system(
    collection_name: str, 
    query: str, 
    n_results: int = 5,
    user_id: str = "admin",
    filtering_mode: str = "none"
) -> dict:
    """
    End-to-end function to retrieve context and answer user query.
    """
    from data_functions.load_document import get_analyzer_and_anonymizer
    analyzer, anonymizer = get_analyzer_and_anonymizer()
    results = analyzer.analyze(text=query, language="en")
    anonymized_query = anonymizer.anonymize(text=query, analyzer_results=results).text

    contexts, diagnostics = retrieve_context(
        collection_name, 
        anonymized_query, 
        n_results=n_results, 
        user_id=user_id, 
        filtering_mode=filtering_mode
    )
    answer = answer_query(anonymized_query, contexts)
    return {
        "answer": answer,
        "contexts": contexts,
        "diagnostics": diagnostics,
        "anonymized_query": anonymized_query
    }

