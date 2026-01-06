import os
import sys
import pandas as pd
from sentence_transformers import SentenceTransformer
import chromadb


def build_combined_text(row: pd.Series) -> str:
    cve_id = str(row.get("CVE_ID", "")).strip()
    cwe_id = str(row.get("CWE_ID", "")).strip()
    severity = str(row.get("Severity", "")).strip()
    language = str(row.get("Language", "")).strip()
    description = str(row.get("CVE_Description", "")).strip()
    vulnerable_code = str(row.get("Affected_Code", "")).strip()
    patch_code = str(row.get("Patch_Code", "")).strip()

    header = f"CVE {cve_id} | CWE {cwe_id} | Severity {severity} | Language {language}".strip()
    parts = [header]
    if description:
        parts.append(f"Description: {description}")
    if vulnerable_code:
        parts.append(f"Vulnerable Code:\n{vulnerable_code}")
    if patch_code:
        parts.append(f"Patched Code:\n{patch_code}")
    return " | ".join(parts)


def main():
    # Path provided by the user
    csv_path = r"D:\\mudassir\\patched_cve_database.csv"

    if not os.path.exists(csv_path):
        print(f"CSV not found at: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print("Loading dataset from CSV...")
    # Use python engine for slightly more tolerant parsing; ensure strings
    df = pd.read_csv(csv_path, encoding="utf-8", engine="python", dtype=str)

    # Fill missing values so concatenation is clean
    df = df.fillna("")

    # Helpful warnings if expected columns are missing, but continue gracefully
    expected_cols = [
        "CVE_ID",
        "CVE_Description",
        "Affected_Code",
        "Patch_Code",
        "Severity",
        "Language",
        "CVSS_Score",
        "CWE_ID",
        "CWE_Name",
        "Vulnerability_Type",
    ]
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        print(f"Warning: missing expected columns: {missing}")

    print("Building combined text for each record...")
    combined_texts = [build_combined_text(row) for _, row in df.iterrows()]

    print("Loading SentenceTransformer model: all-MiniLM-L6-v2 ...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    print("Generating embeddings (batched)...")
    batch_size = 256
    embeddings = []
    for start in range(0, len(combined_texts), batch_size):
        end = start + batch_size
        batch_texts = combined_texts[start:end]
        batch_embeddings = model.encode(
            batch_texts,
            batch_size=batch_size,
            show_progress_bar=True,
            normalize_embeddings=False,
        )
        # Convert to plain lists for Chroma
        embeddings.extend([emb.tolist() for emb in batch_embeddings])

    # Prepare IDs and metadata (ensure unique IDs using index suffix)
    ids = []
    metadatas = []
    for idx, row in df.iterrows():
        cve_id = str(row.get("CVE_ID", "")).strip() or "no-cve"
        doc_id = f"{cve_id}-{idx}"
        ids.append(doc_id)
        meta = {
            "cve_id": str(row.get("CVE_ID", "")),
            "cwe_id": str(row.get("CWE_ID", "")),
            "cwe_name": str(row.get("CWE_Name", "")),
            "cvss_score": str(row.get("CVSS_Score", "")),
            "severity": str(row.get("Severity", "")),
            "language": str(row.get("Language", "")),
            "vulnerability_type": str(row.get("Vulnerability_Type", "")),
        }
        metadatas.append(meta)

    # Initialize persistent Chroma client pointing to a local directory in the workspace
    chroma_dir = os.path.join(os.getcwd(), "chroma")
    os.makedirs(chroma_dir, exist_ok=True)
    print(f"Initializing ChromaDB at: {chroma_dir}")
    client = chromadb.PersistentClient(path=chroma_dir)

    collection_name = "vulnerability_patches"
    collection = client.get_or_create_collection(name=collection_name)

    print(f"Upserting {len(ids)} items into collection '{collection_name}' ...")
    collection.add(ids=ids, embeddings=embeddings, documents=combined_texts, metadatas=metadatas)

    print(f"Done. Collection '{collection_name}' now contains: {collection.count()} items")
    print("You can query with collection.query(query_texts=[...], n_results=5)")


if __name__ == "__main__":
    main()