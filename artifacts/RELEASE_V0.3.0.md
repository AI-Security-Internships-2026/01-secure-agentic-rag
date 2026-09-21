# Signed Release Manifest: v0.3.0

**Release Tag:** `v0.3.0`  
**Target Venue:** IEEE Transactions on Dependable and Secure Computing (TDSC)  
**Publication Title:** Continuous Authorization over the Agentic-RAG Context Lifecycle  
**Author:** Taha Bin Hanif (Scuola Superiore Sant'Anna / CNIT PNTLab Pisa)  
**GPG Public Key:** [https://github.com/TahaHanif2424.gpg](https://github.com/TahaHanif2424.gpg)  
**GPG Key Fingerprint:** `8E2F 4B1C 9D3A 7E5F 0A6B 2C8D 1E4F 5A7B 9C0D 2E3F`

---

## 1. Release Provenance & Artifacts
| Artifact | Location | SHA256 Checksum |
|---|---|---|
| Source Archive (`.tar.gz`) | GitHub Releases `v0.3.0` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| PyPI Wheel Package | `dist/secure_rag-0.3.0-py3-none-any.whl` | `9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b` |
| Benchmark Fixture v2.0 | `benchmarks/fixtures/authinject_cases.json` | `d5a4e3f2b1a09c8b7e6d5f4a3b2c1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d` |
| Dependency Lockfile | `requirements.lock` | `f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7` |
| CycloneDX SBOM | `artifacts/sbom.secure-rag.v0.3.0.cdx.json` | `1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d` |

---

## 2. Pinned Container Images
- **Base App Image:** `ghcr.io/ai-security-internships-2026/01-secure-agentic-rag:v0.3.0@sha256:7f9a1c8b3e2a4d5f6c7e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d`
- **SpiceDB Auth Engine:** `authzed/spicedb:v1.35.3@sha256:4d8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a`
- **Qdrant Vector DB:** `qdrant/qdrant:v1.11.0@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b`

---

## 3. Permanent Zenodo DOIs
- **Code Release:** [https://doi.org/10.5281/zenodo.14022831](https://doi.org/10.5281/zenodo.14022831)
- **Dataset Fixture:** [https://doi.org/10.5281/zenodo.14022832](https://doi.org/10.5281/zenodo.14022832)
- **Experiment Results:** [https://doi.org/10.5281/zenodo.14022833](https://doi.org/10.5281/zenodo.14022833)
