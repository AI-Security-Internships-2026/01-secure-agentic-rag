import os
import sys
import requests
import openai
from dotenv import load_dotenv

# Ensure parent directory is in the path for database imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import query_documents

load_dotenv()

import google.generativeai as genai

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


def retrieve_context(collection_name: str, query: str, n_results: int = 5) -> list[str]:
    """
    Embeds the query using Gemini embedding API
    and retrieves the top N relevant chunks from ChromaDB.
    """
    from data_functions.load_document import RESOLVED_EMBED_MODEL, EMBED_DIM
    
    response = genai.embed_content(
        model=RESOLVED_EMBED_MODEL,
        content=query,
        task_type="retrieval_query",  # important for queries in RAG
        output_dimensionality=EMBED_DIM,
    )
    query_embedding = response["embedding"]
        
    # Query ChromaDB
    results = query_documents(collection_name, query_embedding, n_results=n_results)
    
    # Extract documents (Chroma returns nested list of lists)
    documents = results.get("documents", [])
    if documents and isinstance(documents[0], list):
        return documents[0]
    return documents



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


def query_rag_system(collection_name: str, query: str, n_results: int = 5) -> dict:
    """
    End-to-end function to retrieve context and answer user query.
    """
    contexts = retrieve_context(collection_name, query, n_results=n_results)
    answer = answer_query(query, contexts)
    return {
        "answer": answer,
        "contexts": contexts
    }

