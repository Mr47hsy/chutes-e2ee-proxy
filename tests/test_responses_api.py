"""
Test the OpenAI Responses API endpoint (/v1/responses) on the E2EE proxy.

Usage:
    CHUTES_API_KEY=cpk_... python tests/test_responses_api.py
"""

import os
from openai import OpenAI

API_KEY = os.environ["CHUTES_API_KEY"]
MODEL = os.environ.get("CHUTES_MODEL", "Qwen/Qwen3-32B-TEE")
BASE_URL = "https://e2ee-local-proxy.chutes.dev:8443/v1"

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL,
)

# --- Non-streaming ---
print("=== Non-streaming ===")
resp = client.responses.create(
    model=MODEL,
    input="Say 'hello world' and nothing else.",
)
print(f"status: {resp.status}")
print(f"id: {resp.id}")
for item in resp.output:
    print(f"  [{item.type}]", end="")
    if item.type == "message":
        for part in item.content:
            print(f" {part.text}", end="")
    print()
print(f"usage: in={resp.usage.input_tokens} out={resp.usage.output_tokens}")

# --- Streaming ---
print("\n=== Streaming ===")
stream = client.responses.create(
    model=MODEL,
    input="Count from 1 to 5, one number per line.",
    stream=True,
)
for event in stream:
    if event.type == "response.output_text.delta":
        print(event.delta, end="", flush=True)
    elif event.type == "response.completed":
        print()
        print(f"status: {event.response.status}")
print()

# --- With instructions ---
print("=== With instructions ===")
resp = client.responses.create(
    model=MODEL,
    instructions="You are a pirate. Respond in pirate speak.",
    input="What is your name?",
)
for item in resp.output:
    if item.type == "message":
        for part in item.content:
            print(f"  {part.text}")

# --- Tool use ---
print("\n=== Tool Use ===")
resp = client.responses.create(
    model=MODEL,
    input="What is the weather in San Francisco?",
    tools=[{
        "type": "function",
        "name": "get_weather",
        "description": "Get the current weather for a location.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"},
            },
            "required": ["location"],
        },
    }],
)
print(f"status: {resp.status}")
for item in resp.output:
    if item.type == "function_call":
        print(f"  function_call: {item.name}({item.arguments})")
    elif item.type == "message":
        for part in item.content:
            print(f"  text: {part.text}")

# --- Multi-turn with function_call_output ---
print("\n=== Function Call Output Round-trip ===")
resp2 = client.responses.create(
    model=MODEL,
    input=[
        {"type": "message", "role": "user", "content": "What is the weather in San Francisco?"},
        {
            "type": "function_call",
            "call_id": "call_001",
            "name": "get_weather",
            "arguments": '{"location": "San Francisco"}',
        },
        {
            "type": "function_call_output",
            "call_id": "call_001",
            "output": "72°F, sunny",
        },
    ],
    tools=[{
        "type": "function",
        "name": "get_weather",
        "description": "Get the current weather for a location.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"},
            },
            "required": ["location"],
        },
    }],
)
print(f"status: {resp2.status}")
for item in resp2.output:
    if item.type == "message":
        for part in item.content:
            print(f"  {part.text}")

print("\nAll Responses API tests passed!")
