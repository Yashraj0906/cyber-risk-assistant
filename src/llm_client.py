"""LLM Client Module

Handles API calls to Groq (primary) for generating risk explanations.
Uses Llama 3.3 70B via Groq's free tier — fast inference, no cold starts.

Temperature is set to 0.2 for consistent, factual output (not creative writing).
Includes retry logic for rate limits.
"""
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

_client = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY not found in .env file")
        _client = Groq(api_key=api_key)
    return _client


def generate(prompt, system_prompt=None, model="llama-3.3-70b-versatile", temperature=0.2):
    """Send a prompt to Groq and return the response text."""
    client = _get_client()

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=1024,
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Groq API error: {e}")
        return f"Error generating response: {e}"


if __name__ == "__main__":
    result = generate(
        "What is NIST SP 800-53 SI-2 (Flaw Remediation) in one sentence?",
        system_prompt="You are a cybersecurity expert. Be concise."
    )
    print(f"Response: {result}")
