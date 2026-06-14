"""Seed Qdrant with 50 synthetic historical scan records."""

import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
import hashlib

load_dotenv()

COLLECTION = os.environ.get("QDRANT_COLLECTION", "scan_history")
VECTOR_SIZE = 384

SAMPLE_SCANS = [
    {
        "id": f"scan-{i:03d}",
        "service": svc,
        "cve": cve,
        "severity": sev,
        "scanner": "trivy",
        "date": f"2024-{(i%12)+1:02d}-15",
        "resolved": i % 3 == 0,
    }
    for i, (svc, cve, sev) in enumerate(
        [
            ("user-svc", "CVE-2021-44228", "CRITICAL"),
            ("payment-svc", "CVE-2022-22965", "CRITICAL"),
            ("auth-svc", "CVE-2024-0985", "HIGH"),
            ("order-svc", "CVE-2023-44487", "HIGH"),
            ("api-gw", "CVE-2023-38408", "MEDIUM"),
            ("report-svc", "CVE-2024-21626", "HIGH"),
            ("inventory-svc", "CVE-2023-46604", "CRITICAL"),
            ("notify-svc", "CVE-2023-30589", "MEDIUM"),
            ("admin-svc", "CVE-2024-1234", "HIGH"),
            ("lb-01", "CVE-2023-44487", "HIGH"),
        ]
        * 5
    )
]


def _fake_vector(text: str) -> list[float]:
    """Deterministic fake vector from text hash. Replace with real embeddings in Phase 3."""
    h = int(hashlib.md5(text.encode()).hexdigest(), 16)
    return [(((h >> i) & 0xFF) / 255.0) for i in range(VECTOR_SIZE)]


def seed():
    client = QdrantClient(url=os.environ["QDRANT_URL"])
    client.recreate_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    points = [
        PointStruct(
            id=i,
            vector=_fake_vector(f"{s['service']}-{s['cve']}"),
            payload=s,
        )
        for i, s in enumerate(SAMPLE_SCANS)
    ]
    client.upsert(collection_name=COLLECTION, points=points)
    print(f"Seeded {len(points)} scan records into Qdrant")


if __name__ == "__main__":
    seed()
