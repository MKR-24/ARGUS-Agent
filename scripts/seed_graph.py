"""Seed the Neo4j attack graph"""

import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

URI = os.environ["NEO4J_URI"]
USER = os.environ["NEO4J_USER"]
PASSWORD = os.environ["NEO4J_PASSWORD"]


def seed() -> None:
    cypher = Path("data/seed/attack_graph.cypher").read_text()
    with GraphDatabase.driver(URI, auth=(USER, PASSWORD)) as driver:
        driver.verify_connectivity()
        with driver.session() as session:
            statements = [s.strip() for s in cypher.split(";") if s.strip()]
            for stmt in statements:
                session.run(stmt)
        print("Attack Graph seeded")


if __name__ == "__main__":
    seed()
