import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add src to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from data_functions.query_engine import retrieve_context, answer_query, query_rag_system

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
        
        contexts = retrieve_context("test_collection", "What is database indexing?")
        
        # Verify mocked calls
        mock_embed_content.assert_called_once()
        mock_query_documents.assert_called_once_with("test_collection", [0.1] * 768, n_results=5)
        
        # Verify returned context
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0], "This is a test document snippet about cybersecurity database indexing.")

    @patch("openai.OpenAI")
    def test_answer_query(self, mock_openai_class):
        # Mock OpenAI client instance
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        
        # Mock chat completions
        mock_completions = MagicMock()
        mock_client.chat.completions = mock_completions
        
        # Mock return structure choices[0].message.content
        mock_response = MagicMock()
        mock_message = MagicMock()
        mock_message.content = "This is a mocked answer from Groq."
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_completions.create.return_value = mock_response
        
        contexts = ["Cybersecurity context details."]
        answer = answer_query("What are the details?", contexts)
        
        # Verify mock instantiation and call
        mock_openai_class.assert_called_once()
        mock_completions.create.assert_called_once()
        
        # Verify answer content
        self.assertEqual(answer, "This is a mocked answer from Groq.")

    @patch("google.generativeai.embed_content")
    @patch("data_functions.query_engine.query_documents")
    @patch("openai.OpenAI")
    def test_query_rag_system(self, mock_openai_class, mock_query_documents, mock_embed_content):
        # Setup mock for embeddings
        mock_embed_content.return_value = {"embedding": [0.1] * 768}

        mock_query_documents.return_value = {
            "documents": [["Context chunk 1"]]
        }
        
        # Setup mock for Groq completions
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_completions = MagicMock()
        mock_client.chat.completions = mock_completions
        
        mock_response = MagicMock()
        mock_message = MagicMock()
        mock_message.content = "Mock answer text from Groq."
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_completions.create.return_value = mock_response
        
        result = query_rag_system("test_col", "Mock query")
        
        # Verify results
        self.assertEqual(result["answer"], "Mock answer text from Groq.")
        self.assertEqual(result["contexts"], ["Context chunk 1"])


if __name__ == "__main__":
    unittest.main()
