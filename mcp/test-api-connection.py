#!/usr/bin/env python3
"""Test script to verify MCP server can connect to health API"""

import asyncio
import httpx

API_BASE_URL = "http://localhost:8000"
REQUEST_TIMEOUT = 5.0

async def test_connection():
    """Test connection to health API"""

    endpoints = [
        "/health/quick",
        "/health/database",
        "/health/service/rag-api"
    ]

    print(f"Testing connection to {API_BASE_URL}...")
    print("-" * 60)

    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        for endpoint in endpoints:
            url = f"{API_BASE_URL}{endpoint}"
            try:
                print(f"\nTesting: {url}")
                response = await client.get(url)
                response.raise_for_status()
                result = response.json()
                print(f"  ✅ SUCCESS: {result.get('status', 'ok')}")
                print(f"  Response: {result}")
            except httpx.TimeoutException:
                print(f"  ❌ TIMEOUT after {REQUEST_TIMEOUT}s")
            except httpx.HTTPError as e:
                print(f"  ❌ HTTP ERROR: {e}")
                if hasattr(e, 'response') and e.response:
                    print(f"  Status Code: {e.response.status_code}")
            except Exception as e:
                print(f"  ❌ UNKNOWN ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
