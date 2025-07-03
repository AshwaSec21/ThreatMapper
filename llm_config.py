import os

def get_llm_config(provider: str = None, model: str = None, api_key: str = None):
    """
    Returns LLM config based on selected provider. Uses .env as fallback if values not provided.
    """
    provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()

    if provider == "openai":
        return {
            "provider": "openai",
            "model": model or "gpt-3.5-turbo",  # or "gpt-4.1-nano"
            "api_key": api_key or os.getenv("OPENAI_API_KEY"),
            "url": "https://api.openai.com/v1/chat/completions",
            "headers": lambda k: {
                "Authorization": f"Bearer {k}"
            }
        }

    elif provider == "mistral":
        return {
            "provider": "mistral",
            "model": model or "mistralai/mistral-7b-instruct",
            "api_key": api_key or os.getenv("OPENROUTER_API_KEY"),
            "url": "https://openrouter.ai/api/v1/chat/completions",
            "headers": lambda k: {
                "Authorization": f"Bearer {k}",
                "X-Title": "ThreatMatchingTool"
            }
        }

    elif provider == "groq":
        return {
            "provider": "groq",
            "model": model or "mixtral-8x7b-32768",
            "api_key": api_key or os.getenv("GROQ_API_KEY"),
            "url": "https://api.groq.com/openai/v1/chat/completions",
            "headers": lambda k: {
                "Authorization": f"Bearer {k}",
                "Content-Type": "application/json"
            }
        }

    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
