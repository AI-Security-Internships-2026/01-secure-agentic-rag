import unittest
from unittest.mock import MagicMock, patch

from data_functions.load_document import anonymize_text, get_analyzer_and_anonymizer, load_and_chunk_pdf


class TestLoadDocument(unittest.TestCase):
    def test_anonymizer_available(self):
        analyzer, anonymizer = get_analyzer_and_anonymizer()
        redacted = anonymizer.anonymize(text="hello", analyzer_results=analyzer.analyze(text="hello", language="en"))
        self.assertTrue(hasattr(redacted, "text"))

    @patch("data_functions.load_document.PdfReader")
    def test_load_and_chunk_pdf(self, mock_reader):
        page = MagicMock()
        page.extract_text.return_value = "Qdrant stores vectors for authorization-first retrieval."
        mock_reader.return_value.pages = [page]
        with patch("data_functions.load_document.anonymize_text", side_effect=lambda t: t):
            chunks = load_and_chunk_pdf("dummy.pdf")
        self.assertTrue(any("Qdrant" in c for c in chunks))
