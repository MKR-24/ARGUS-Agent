import os
import logging
from typing import Any
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from neo4j import AsyncGraphDatabase

from .models import AttackPath, ServiceInfo

load_dotenv()
logger = logging.getLogger(__name__)

mcp = FastMCP("graph-server")
_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = AsyncGraphDatabase.driver(
            os.environ["NEO4J_URI"],
            auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]),
        )
    return _driver


@mcp.tool()
async def get_service_info(service_id: str) -> dict[str, Any]:
    # Sanitise input — Neo4j uses parameterised queries so injection is prevented,
    # but we still reject obvious garbage early.
    service_id = service_id.strip()
    if not service_id or len(service_id) > 100:
        return {"error": "Invalid service_id"}
    async with get_driver().session() as session:
        res = await session.run(
            """
            MATCH (s:Node {id:$sid})
            OPTIONAL MATCH (s)-[:AFFECTED_BY]->(c:CVE)
            RETURN s,collect(c.id) AS cves
        """,
            sid=service_id,
        )
        record = await res.single()
        if not record:
            return {"error": f"Service '{service_id}' not found"}
        node = record["S"]
        return ServiceInfo(
            id=node["id"],
            name=node["name"],
            type=node["type"],
            version=node.get("version"),
            cves=record["cves"],
        ).model.dump()


@mcp.tool()
async def find_attack_paths(target_service_id: str) -> dict[str, Any]:
    """
    Find shortest attack paths from the internet to the target service.
    Returns paths with hop count and internet reachability flag.
    """
    target_service_id = target_service_id.strip()
    if not target_service_id:
        return {"error": "target_service_id required"}
    async with get_driver().session() as session:
        res = await session.run(
            """
            MATCH path=shortestPath(
                (internet:Node {id: 'internet'})-[:CONNECTS_TO*]->(target:Node {id: $tid})
            )
            RETURN [n IN nodes(path) | n.id] AS path_nodes, length(path) AS hops
            LIMIT 5
            """,
            tid=target_service_id,
        )
        records = await res.data()

    if not records:
        return {
            "paths": [],
            "reachable_from_internet": False,
            "message": f"No path from internet to '{target_service_id}'",
        }
    paths = [
        AttackPath(
            path=r["path_nodes"],
            hop_count=r["hops"],
            reachable_from_internet=True,
        ).model_dump()
        for r in records
    ]
    return {"paths": paths, "reachable_from_internet": True}


if __name__ == "__main__":
    mcp.run(transport="stdio")
