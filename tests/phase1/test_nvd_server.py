"""Test NVD MCP server — mocked HTTP to avoid hitting real API in CI."""

import pytest
from unittest.mock import AsyncMock, patch

from mcp_servers.nvd.server import get_cve_details


@pytest.mark.asyncio
async def test_invalid_cve_id_rejected():
    result = await get_cve_details("NOT-A-CVE")
    assert "error" in result


@pytest.mark.asyncio
async def test_valid_cve_returns_detail():
    mock_nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "AV:N/AC:L",
                                }
                            }
                        ]
                    },
                    "published": "2021-12-10",
                    "references": [],
                }
            }
        ]
    }
    mock_epss = {"data": [{"epss": "0.97", "percentile": "0.99"}]}

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.side_effect = [
            AsyncMock(json=lambda: mock_nvd, raise_for_status=lambda: None),
            AsyncMock(json=lambda: mock_epss, raise_for_status=lambda: None),
        ]
        result = await get_cve_details("CVE-2021-44228")

    assert result["cve_id"] == "CVE-2021-44228"
    assert result["cvss_v3_score"] == 10.0
    assert result["epss_score"] == pytest.approx(0.97)
