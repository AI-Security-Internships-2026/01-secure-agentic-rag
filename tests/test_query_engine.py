import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add src to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from langchain_core.messages import AIMessage
from data_functions.query_engine import retrieve_context, query_rag_system

class TestQueryEngine(unittest.TestCase):
    
    @patch("google.generativeai.embed_content")
    @patch("data_functions.query_engine.query_documents")
    def test_retrieve_context(self, mock_query_documents, mock_embed_content):
        # Mock genai.embed_content response
        mock_embed_content.return_value = {"embedding": [0.1] * 768}
        
        # Mock query_documents return value
        mock_query_documents.return_value = {
            "documents": [["This is a test document snippet about cybersecurity database indexing."]]
        }
        
        contexts, _ = retrieve_context("test_collection", "What is database indexing?")
        
        # Verify mocked calls
        mock_embed_content.assert_called_once()
        mock_query_documents.assert_called_once_with("test_collection", [0.1] * 768, n_results=5, where=None)
        
        # Verify returned context
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0], "This is a test document snippet about cybersecurity database indexing.")

    @patch("google.generativeai.embed_content")
    @patch("data_functions.query_engine.query_documents")
    @patch("data_functions.query_engine.ChatOpenAI")
    def test_query_rag_system(self, mock_chat_openai, mock_query_documents, mock_embed_content):
        # Setup mock for embeddings
        mock_embed_content.return_value = {"embedding": [0.1] * 768}

        mock_query_documents.return_value = {
            "documents": [["Context chunk 1"]]
        }
        
        # Setup ChatOpenAI mock instances and their invoke calls
        mock_llm_instance = MagicMock()
        mock_chat_openai.return_value = mock_llm_instance
        
        msg_safe = AIMessage(content="SAFE")
        msg_chunk_safe = AIMessage(content="SAFE") # For active indirect injection scan
        msg_verify = AIMessage(content="Chunk 1:\nRELEVANT: YES\nSCORE: 5\n")
        msg_gen = AIMessage(content="Mock answer text from Groq.")
        msg_grounded = AIMessage(content="PASS")
        
        mock_llm_instance.side_effect = [
            msg_safe,       # For injection guardrail
            msg_chunk_safe, # For indirect injection check
            msg_verify,     # For relevance evaluation/verification
            msg_gen,        # For generation
            msg_grounded    # For groundedness evaluation
        ]
        
        result = query_rag_system("test_col", "Mock query")
        
        # Verify results (Groq is anonymized to <LOCATION> by the output PII guardrail)
        self.assertEqual(result["answer"], "Mock answer text from <LOCATION>.")
        self.assertEqual(result["contexts"], ["Context chunk 1"])

    @patch("google.generativeai.embed_content")
    @patch("data_functions.query_engine.query_documents")
    @patch("data_functions.query_engine.ChatOpenAI")
    def test_query_rag_system_with_rewrite(self, mock_chat_openai, mock_query_documents, mock_embed_content):
        # Mock embed_content
        mock_embed_content.return_value = {"embedding": [0.1] * 768}
        
        # First query_documents returns no documents, then second returns documents
        mock_query_documents.side_effect = [
            {"documents": [["Context chunk 1"]]},
            {"documents": [["Context chunk 2"]]}
        ]
        
        mock_llm_instance = MagicMock()
        mock_chat_openai.return_value = mock_llm_instance
        
        # Setup side effect responses
        msg_safe = AIMessage(content="SAFE")
        msg_chunk1_safe = AIMessage(content="SAFE")
        msg_verify_fail = AIMessage(content="Chunk 1:\nRELEVANT: NO\nSCORE: 1\n")
        msg_rewrite = AIMessage(content="New reformulated query")
        msg_chunk2_safe = AIMessage(content="SAFE")
        msg_verify_pass = AIMessage(content="Chunk 1:\nRELEVANT: YES\nSCORE: 5\n")
        msg_gen = AIMessage(content="Answer based on context 2.")
        msg_grounded = AIMessage(content="PASS")
        
        mock_llm_instance.side_effect = [
            msg_safe,          # guard_input (injection)
            msg_chunk1_safe,   # verify_and_rerank (Chunk 1 injection check)
            msg_verify_fail,   # verify_and_rerank (Chunk 1 marked irrelevant)
            msg_rewrite,       # rewrite_query
            msg_chunk2_safe,   # verify_and_rerank (Chunk 2 injection check)
            msg_verify_pass,   # verify_and_rerank (Chunk 2 marked relevant)
            msg_gen,           # generate
            msg_grounded       # guard_output (groundedness)
        ]
        
        result = query_rag_system("test_col", "Mock query")
        
        # "Answer" is anonymized to <ORGANIZATION> by the output PII guardrail
        self.assertEqual(result["answer"], "<ORGANIZATION> based on context 2.")
        self.assertEqual(result["contexts"], ["Context chunk 2"])
        self.assertEqual(result["anonymized_query"], "New reformulated query")

    @patch("google.generativeai.embed_content")
    @patch("data_functions.query_engine.query_documents")
    @patch("data_functions.query_engine.ChatOpenAI")
    def test_query_rag_system_with_indirect_injection(self, mock_chat_openai, mock_query_documents, mock_embed_content):
        # Setup mock for embeddings
        mock_embed_content.return_value = {"embedding": [0.1] * 768}
        
        # First query_documents returns poisoned chunk, second returns clean chunk
        mock_query_documents.side_effect = [
            {"documents": [["Poisoned context chunk"]]},
            {"documents": [["Clean context chunk"]]}
        ]
        
        mock_llm_instance = MagicMock()
        mock_chat_openai.return_value = mock_llm_instance
        
        msg_safe = AIMessage(content="SAFE")
        msg_chunk1_poisoned = AIMessage(content="INJECTION") # Chunk 1 active scanner flags injection
        msg_rewrite = AIMessage(content="New reformulated query")
        msg_chunk2_safe = AIMessage(content="SAFE") # Chunk 2 active scanner flags safe
        msg_verify = AIMessage(content="Chunk 1:\nRELEVANT: YES\nSCORE: 5\n")
        msg_gen = AIMessage(content="Answer based on context 2.")
        msg_grounded = AIMessage(content="PASS")
        
        mock_llm_instance.side_effect = [
            msg_safe,            # guard_input (injection)
            msg_chunk1_poisoned, # verify_and_rerank (Chunk 1 flagged, discarded)
            msg_rewrite,         # rewrite_query (no contexts left)
            msg_chunk2_safe,     # verify_and_rerank (Chunk 2 checked and safe)
            msg_verify,          # verify_and_rerank (Chunk 2 graded relevant)
            msg_gen,             # generate
            msg_grounded         # guard_output (groundedness)
        ]
        
        result = query_rag_system("test_col", "Mock query")
        
        # Verify that indirect injection alert is recorded, and the poisoned chunk discarded
        self.assertTrue(result["diagnostics"].get("indirect_injection_detected"))
        self.assertEqual(result["contexts"], ["Clean context chunk"])
        self.assertEqual(result["answer"], "<ORGANIZATION> based on context 2.")


if __name__ == "__main__":
    unittest.main()

