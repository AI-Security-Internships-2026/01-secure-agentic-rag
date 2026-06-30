import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add src to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from data_functions.load_document import load_and_chunk_pdf, get_analyzer_and_anonymizer

class TestLoadDocument(unittest.TestCase):
    
    @patch("data_functions.load_document.PDFReader")
    def test_load_and_chunk_pdf_anonymization(self, mock_pdf_reader_class):
        # Create a mock PDFReader instance
        mock_pdf_reader_instance = MagicMock()
        mock_pdf_reader_class.return_value = mock_pdf_reader_instance
        
        # Define mock documents returned by load_data
        mock_doc = MagicMock()
        mock_doc.text = "My name is John Smith. Contact me at john.smith@gmail.com or phone +1-555-555-5555."
        mock_pdf_reader_instance.load_data.return_value = [mock_doc]
        
        # Run load_and_chunk_pdf
        # Since we might not have the SpaCy model installed in the environment where test runs,
        # we can mock get_analyzer_and_anonymizer or mock the AnalyzerEngine and AnonymizerEngine.
        # Let's mock get_analyzer_and_anonymizer to return mock analyzer/anonymizer so the test is hermetic.
        
        mock_analyzer = MagicMock()
        mock_anonymizer = MagicMock()
        
        # Mock analyzer.analyze to return a dummy list of results
        mock_analyzer.analyze.return_value = []
        
        # Mock anonymizer.anonymize to return redacted text
        mock_redacted_result = MagicMock()
        mock_redacted_result.text = "My name is <PERSON>. Contact me at <EMAIL_ADDRESS> or phone <PHONE_NUMBER>."
        mock_anonymizer.anonymize.return_value = mock_redacted_result
        
        with patch("data_functions.load_document.get_analyzer_and_anonymizer", return_value=(mock_analyzer, mock_anonymizer)):
            chunks = load_and_chunk_pdf("dummy_path.pdf")
            
            # Verify PDFReader was called with the correct file path
            mock_pdf_reader_instance.load_data.assert_called_once_with(file="dummy_path.pdf")
            
            # Verify analyzer was called with the extracted text
            mock_analyzer.analyze.assert_called_once_with(text=mock_doc.text, language="en")
            
            # Verify anonymizer was called with the analysis results
            mock_anonymizer.anonymize.assert_called_once_with(text=mock_doc.text, analyzer_results=[])
            
            # Verify that the returned chunks contain the redacted/anonymized text
            self.assertTrue(any("<PERSON>" in chunk for chunk in chunks))
            self.assertTrue(any("<EMAIL_ADDRESS>" in chunk for chunk in chunks))

    @patch("data_functions.load_document.os.getenv")
    def test_register_custom_recognizers(self, mock_getenv):
        # We mock getenv to return some dummy values
        def side_effect(key, default=None):
            if key == "PRESIDIO_CUSTOM_DENY_LIST":
                return "SecretProject, AlphaTeam"
            elif key == "PRESIDIO_CUSTOM_PATTERNS":
                return '[{"entity": "STUDENT_ID", "regex": "\\\\bSTD-\\\\d{6}\\\\b", "score": 0.95}]'
            return default
        mock_getenv.side_effect = side_effect
        
        # Create a mock analyzer with a mock registry
        mock_analyzer = MagicMock()
        mock_analyzer.registry = MagicMock()
        
        from data_functions.load_document import _register_custom_recognizers
        _register_custom_recognizers(mock_analyzer)
        
        # Verify that registry.add_recognizer was called twice (once for deny list, once for regex)
        self.assertEqual(mock_analyzer.registry.add_recognizer.call_count, 2)
        
        # Inspect mock calls to ensure correct types/entities
        calls = mock_analyzer.registry.add_recognizer.call_args_list
        entity_types = []
        for call in calls:
            entity_types.extend(call[0][0].supported_entities)
        
        self.assertIn("CUSTOM_DENY_LIST", entity_types)
        self.assertIn("STUDENT_ID", entity_types)



if __name__ == "__main__":
    unittest.main()

