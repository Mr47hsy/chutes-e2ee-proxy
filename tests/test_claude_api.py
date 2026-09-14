"""
Test the Claude Messages API endpoint (/v1/messages) on the E2EE proxy.

Usage:
    CHUTES_API_KEY=cpk_... python tests/test_claude_api.py
"""

import os
import anthropic

API_KEY = os.environ["CHUTES_API_KEY"]
MODEL = os.environ.get("CHUTES_MODEL", "Qwen/Qwen3-32B-TEE")
BASE_URL = "https://e2ee-local-proxy.chutes.dev:8443"

client = anthropic.Anthropic(
    api_key=API_KEY,
    base_url=BASE_URL,
)

# --- Non-streaming ---
print("=== Non-streaming ===")
resp = client.messages.create(
    model=MODEL,
    max_tokens=128,
    messages=[{"role": "user", "content": "Say 'hello world' and nothing else."}],
)
print(f"stop_reason: {resp.stop_reason}")
for block in resp.content:
    print(f"  [{block.type}] {getattr(block, 'text', '')}")
print(f"usage: in={resp.usage.input_tokens} out={resp.usage.output_tokens}")

# --- Streaming ---
print("\n=== Streaming ===")
with client.messages.stream(
    model=MODEL,
    max_tokens=128,
    messages=[{"role": "user", "content": "Count from 1 to 5, one number per line."}],
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
print()
msg = stream.get_final_message()
print(f"stop_reason: {msg.stop_reason}")
print(f"usage: in={msg.usage.input_tokens} out={msg.usage.output_tokens}")

# --- Tool use ---
print("\n=== Tool Use ===")
resp = client.messages.create(
    model=MODEL,
    max_tokens=256,
    messages=[{"role": "user", "content": "What is the weather in San Francisco?"}],
    tools=[{
        "name": "get_weather",
        "description": "Get the current weather for a location.",
        "input_schema": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"},
            },
            "required": ["location"],
        },
    }],
)
print(f"stop_reason: {resp.stop_reason}")
for block in resp.content:
    if block.type == "tool_use":
        print(f"  tool_use: {block.name}({block.input})")
    elif block.type == "text":
        print(f"  text: {block.text}")

# --- Multi-turn with tool result ---
print("\n=== Tool Result Round-trip ===")
resp2 = client.messages.create(
    model=MODEL,
    max_tokens=256,
    messages=[
        {"role": "user", "content": "What is the weather in San Francisco?"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check the weather."},
                {
                    "type": "tool_use",
                    "id": "call_001",
                    "name": "get_weather",
                    "input": {"location": "San Francisco"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "call_001",
                    "content": "72°F, sunny",
                },
            ],
        },
    ],
    tools=[{
        "name": "get_weather",
        "description": "Get the current weather for a location.",
        "input_schema": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"},
            },
            "required": ["location"],
        },
    }],
)
print(f"stop_reason: {resp2.stop_reason}")
for block in resp2.content:
    print(f"  [{block.type}] {getattr(block, 'text', '')}")

print("\nAll Claude API tests passed!")
