"""
title: Test Tools
author: RAG-Scan-Stack
version: 1.0.0
description: Simple test tools to verify tool calling works
"""

import json
import requests
from datetime import datetime
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        MCP_TEST_URL: str = Field(
            default="https://mcp-test:8020",
            description="URL of the MCP test server"
        )

    def __init__(self):
        self.valves = self.Valves()

    def echo_message(self, message: str) -> str:
        """
        Echo back the input message. Test basic tool calling.

        :param message: Message to echo back
        :return: The echoed message
        """
        return f"Echo: {message}"

    def get_current_time(self) -> str:
        """
        Get the current server time.

        :return: Current date and time
        """
        return f"Current time: {datetime.now().isoformat()}"

    def add_numbers(self, a: float, b: float) -> str:
        """
        Add two numbers together.

        :param a: First number
        :param b: Second number
        :return: Sum of the two numbers
        """
        result = a + b
        return f"{a} + {b} = {result}"

    def greet_person(self, name: str) -> str:
        """
        Generate a greeting for a person.

        :param name: Name of the person to greet
        :return: A greeting message
        """
        return f"Hello, {name}! Welcome to RAG-Scan-Stack."

    def check_mcp_test_server(self) -> str:
        """
        Check if the MCP test server is running.

        :return: Health status
        """
        try:
            r = requests.get(f"{self.valves.MCP_TEST_URL}/health", timeout=10)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def check_all_services(self) -> str:
        """
        Check health of all RAG-Scan-Stack services.

        :return: Service health status
        """
        services = {
            "mcp_server": "https://mcp-server:8016/health",
            "mcp_test": "https://mcp-test:8020/health",
            "autogen_agents": "https://autogen-agents:8015/health",
            "rag_api": "https://rag-api:8000/health",
            "nmap_scanner": "https://nmap_scanner:8012/health",
        }
        results = {}
        for name, url in services.items():
            try:
                r = requests.get(url, timeout=5)
                results[name] = "healthy" if r.status_code == 200 else "unhealthy"
            except:
                results[name] = "unreachable"
        return json.dumps(results, indent=2)
