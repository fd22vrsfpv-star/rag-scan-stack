#!/usr/bin/env python3
"""Simple proxy to log Cline/Continue -> vLLM requests (OpenAI-compatible API)"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
from datetime import datetime
import time

VLLM_URL = "http://localhost:8100"
PROXY_PORT = 8101

class LoggingProxy(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        # Log the request
        print(f"\n{'='*70}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] REQUEST: POST {self.path}")
        print(f"{'='*70}")
        try:
            data = json.loads(body)
            print(f"Model: {data.get('model')}")
            print(f"Stream: {data.get('stream', False)}")
            print(f"Temperature: {data.get('temperature', 'default')}")
            print(f"Max tokens: {data.get('max_tokens', 'default')}")

            messages = data.get('messages', [])
            print(f"Messages: {len(messages)}")
            for i, msg in enumerate(messages):
                role = msg.get('role', '?')
                content = msg.get('content', '')
                if isinstance(content, str):
                    content_preview = content[:200]
                else:
                    content_preview = str(content)[:200]
                print(f"  [{i}] {role}: {content_preview}...")

            if 'tools' in data:
                print(f"\nTOOLS PROVIDED: {len(data['tools'])} tools")
                for t in data['tools'][:10]:
                    func = t.get('function', {})
                    print(f"  - {func.get('name', '?')}")
            else:
                print("\nNO TOOLS in request")

            if 'tool_choice' in data:
                print(f"Tool choice: {data['tool_choice']}")

        except Exception as e:
            print(f"Parse error: {e}")
            print(body[:500])

        # Forward to vLLM
        req = urllib.request.Request(
            f"{VLLM_URL}{self.path}",
            data=body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': self.headers.get('Authorization', '')
            }
        )

        try:
            start_time = time.time()

            # Check if streaming
            is_streaming = json.loads(body).get('stream', False)

            with urllib.request.urlopen(req) as resp:
                if is_streaming:
                    # Handle streaming response
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()

                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] STREAMING RESPONSE...")
                    full_content = ""
                    tool_calls = []

                    for line in resp:
                        self.wfile.write(line)
                        self.wfile.flush()

                        # Parse SSE data
                        line_str = line.decode('utf-8').strip()
                        if line_str.startswith('data: ') and line_str != 'data: [DONE]':
                            try:
                                chunk = json.loads(line_str[6:])
                                delta = chunk.get('choices', [{}])[0].get('delta', {})
                                if 'content' in delta and delta['content']:
                                    full_content += delta['content']
                                if 'tool_calls' in delta:
                                    tool_calls.extend(delta['tool_calls'])
                            except:
                                pass

                    elapsed = time.time() - start_time
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] STREAM COMPLETE ({elapsed:.2f}s)")
                    print(f"Content preview: {full_content[:300]}...")
                    if tool_calls:
                        print(f"Tool calls: {json.dumps(tool_calls, indent=2)[:500]}")
                else:
                    # Handle non-streaming response
                    response_body = resp.read()
                    elapsed = time.time() - start_time

                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] RESPONSE ({elapsed:.2f}s)")
                    try:
                        resp_data = json.loads(response_body)

                        # OpenAI format response
                        choices = resp_data.get('choices', [])
                        if choices:
                            message = choices[0].get('message', {})
                            content = message.get('content', '')
                            if content:
                                print(f"Content: {content[:300]}...")

                            if 'tool_calls' in message:
                                print(f"TOOL CALLS:")
                                for tc in message['tool_calls']:
                                    func = tc.get('function', {})
                                    print(f"  - {func.get('name')}: {func.get('arguments', '')[:100]}")

                        # Token usage
                        usage = resp_data.get('usage', {})
                        if usage:
                            prompt_tokens = usage.get('prompt_tokens', 0)
                            completion_tokens = usage.get('completion_tokens', 0)
                            total_tokens = usage.get('total_tokens', 0)
                            tokens_per_sec = completion_tokens / elapsed if elapsed > 0 else 0
                            print(f"Tokens: {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total ({tokens_per_sec:.1f} tok/s)")

                    except Exception as e:
                        print(f"Parse error: {e}")
                        print(response_body[:300])

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(response_body)

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            print(f"HTTP ERROR {e.code}: {error_body[:500]}")
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(error_body.encode())
        except Exception as e:
            print(f"ERROR: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_GET(self):
        """Handle GET requests (e.g., /v1/models)"""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] GET {self.path}")

        req = urllib.request.Request(
            f"{VLLM_URL}{self.path}",
            headers={'Authorization': self.headers.get('Authorization', '')}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read()
                print(f"Response: {body[:200].decode('utf-8')}")
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            error_body = e.read()
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(error_body)

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == "__main__":
    print(f"{'='*70}")
    print(f"vLLM Debug Proxy")
    print(f"{'='*70}")
    print(f"Upstream:  {VLLM_URL}")
    print(f"Proxy:     http://localhost:{PROXY_PORT}")
    print(f"")
    print(f"Configure Cline with:")
    print(f"  Base URL: http://localhost:{PROXY_PORT}/v1")
    print(f"  API Key:  dummy (or your VLLM_API_KEY)")
    print(f"  Model:    mistralai/Mistral-7B-Instruct-v0.3")
    print(f"{'='*70}")
    print(f"Watching for requests...\n")
    HTTPServer(('0.0.0.0', PROXY_PORT), LoggingProxy).serve_forever()
