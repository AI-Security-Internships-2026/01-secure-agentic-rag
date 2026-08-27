"""Optional Chroma → Qdrant copy."""

import argparse

from secure_rag.retrieval.ingest import migrate_chroma


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("chroma_dir", default="chroma_db", nargs="?")
    args = parser.parse_args()
    print(migrate_chroma(args.chroma_dir))


if __name__ == "__main__":
    main()
