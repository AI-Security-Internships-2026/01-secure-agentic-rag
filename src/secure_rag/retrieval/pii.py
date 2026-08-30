from __future__ import annotations

import json
import logging
import re
from functools import lru_cache

logger = logging.getLogger("secure_rag.pii")

_splitter = re.compile(r"(?<=[.!?])\s+")

# Direct identifiers only. Broad contextual entities such as DATE_TIME, NRP, LOCATION and
# ORGANIZATION are excluded: they fire on ordinary domain vocabulary ("Quarterly close"),
# which strips the terms retrieval and generation depend on without protecting any subject.
DEFAULT_PII_ENTITIES = (
    "CREDIT_CARD",
    "CRYPTO",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "MEDICAL_LICENSE",
    "PERSON",
    "PHONE_NUMBER",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_SSN",
)


def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> list[str]:
    if not text.strip():
        return []
    words = text.split()
    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = min(len(words), start + max(1, chunk_size // 5))
        chunks.append(" ".join(words[start:end]))
        if end == len(words):
            break
        start = max(end - max(1, overlap // 5), start + 1)
    return chunks


@lru_cache
def _engines():
    custom_entities: list[str] = []
    try:
        from presidio_analyzer import AnalyzerEngine, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine
        from secure_rag.settings import get_settings

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
        )
        analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
        settings = get_settings()
        if settings.presidio_custom_deny_list:
            deny_list = [item.strip() for item in settings.presidio_custom_deny_list.split(",") if item.strip()]
            if deny_list:
                analyzer.registry.add_recognizer(
                    PatternRecognizer(supported_entity="CUSTOM_DENY_LIST", deny_list=deny_list, deny_list_score=1.0)
                )
                custom_entities.append("CUSTOM_DENY_LIST")
        if settings.presidio_custom_patterns:
            from presidio_analyzer import Pattern

            for item in json.loads(settings.presidio_custom_patterns):
                analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity=item["entity"],
                        patterns=[Pattern(name=item["entity"], regex=item["regex"], score=float(item.get("score", 0.85)))],
                    )
                )
                custom_entities.append(item["entity"])
        return analyzer, AnonymizerEngine(), tuple(custom_entities)
    except Exception as exc:
        logger.warning("Presidio unavailable (%s); using regex redaction", exc)
        return None, None, ()


def _requested_entities(custom_entities: tuple[str, ...]) -> list[str]:
    from secure_rag.settings import get_settings

    configured = get_settings().pii_entities
    base = [item.strip().upper() for item in configured.split(",") if item.strip()] or list(DEFAULT_PII_ENTITIES)
    return base + [entity for entity in custom_entities if entity not in base]


def anonymize_text(text: str) -> str:
    from secure_rag.settings import get_settings

    analyzer, anonymizer, custom_entities = _engines()
    if analyzer is None or anonymizer is None:
        return re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[EMAIL]", text)
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=_requested_entities(custom_entities),
        score_threshold=get_settings().pii_score_threshold,
    )
    return anonymizer.anonymize(text=text, analyzer_results=results).text
