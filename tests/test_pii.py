import unittest

from secure_rag.retrieval.pii import _engines, anonymize_text

PRESIDIO_AVAILABLE = _engines()[0] is not None


class TestPiiPrecision(unittest.TestCase):
    @unittest.skipUnless(PRESIDIO_AVAILABLE, "Presidio/spaCy model not installed; regex fallback only covers email")
    def test_direct_identifiers_are_removed(self):
        redacted = anonymize_text(
            "Contact alice.smith@example.com or +1-415-555-0132. SSN 456-78-1234, card 4111111111111111."
        )
        for identifier in ("alice.smith@example.com", "415-555-0132", "456-78-1234", "4111111111111111"):
            self.assertNotIn(identifier, redacted)

    def test_domain_vocabulary_survives_redaction(self):
        """Retrieval and generation depend on these terms; they are not PII."""
        text = "Quarterly close requires dual control. Payroll hash CANARY_FIN_A1."
        redacted = anonymize_text(text)
        self.assertIn("Quarterly", redacted)
        self.assertIn("dual control", redacted)
        self.assertIn("CANARY_FIN_A1", redacted)
