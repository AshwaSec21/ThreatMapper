import os
import requests
from dotenv import load_dotenv
import time
import httpx
import hashlib
import shelve
from llm_config import get_llm_config
_llm_response_cache = {}

CACHE_PATH = "llm_cache.db"  # Persistent cache on disk

# Load environment variables from .env file
load_dotenv()
#OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

#query_llm not used any more
def query_llm(prompt: str, model: str = "mistralai/mistral-7b-instruct") -> str:
    """
    Send a prompt to OpenAPI's LLM API and return the response.
    Default model is Mistral-7B.
    """
    if not OPENAI_API_KEY:
        return "[LLM ERROR] Missing OpenAI  API key."

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst helping map threats to system requirements."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 512
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[LLM ERROR] {str(e)}"


def hash_prompt(prompt: str, model: str) -> str:
    key_string = f"{model}:{prompt}"
    return hashlib.sha256(key_string.encode("utf-8")).hexdigest()

def call_llm(
    prompt: str,
    provider=None,
    model=None,
    api_key=None,
    max_tokens=2048,
    temperature=0.0,
    print_logs=False,
    use_cache=False
) -> str:
    config = get_llm_config(provider, model, api_key)

    if not config.get("api_key"):
        return f"[LLM ERROR] Missing API key for provider: {config['provider']}"

    headers = config["headers"](config["api_key"]) if callable(config["headers"]) else config["headers"]

    # Hash prompt to use as cache key
    cache_key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    if use_cache and cache_key in _llm_response_cache:
        if print_logs:
            print("🧠 Using cached response")
        return _llm_response_cache[cache_key]

    payload = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert mapping threats to requirements."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": temperature
    }

    try:
        response = httpx.post(config["url"], headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()["choices"][0]["message"]["content"].strip()

        if use_cache:
            _llm_response_cache[cache_key] = result

        if print_logs:
            print("🔍 Raw LLM response:\n", result)

        return result

    except Exception as e:
        return f"[LLM ERROR] {str(e)}"

def clear_cache_file():
    if os.path.exists(".cache/llm_cache.json"):
        os.remove(".cache/llm_cache.json")
