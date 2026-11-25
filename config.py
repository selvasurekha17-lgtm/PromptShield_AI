"""Configuration module for PromptShield AI.

Loads environment variables and initializes the Gemini API client safely.
"""

import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Load environment variables from .env
load_dotenv()

# Retrieve API key and Model Name
API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Default HTTP timeout for Gemini API calls: 35,000 milliseconds (35 seconds per attempt)
DEFAULT_TIMEOUT_MS: int = int(os.getenv("GEMINI_TIMEOUT_MS", "35000"))

# Initialize Gemini client safely with explicit HTTP timeout
client = None
if API_KEY:
    try:
        http_opts = types.HttpOptions(timeout=DEFAULT_TIMEOUT_MS)
        client = genai.Client(api_key=API_KEY, http_options=http_opts)
    except Exception:
        client = None


def is_api_configured() -> bool:
    """Check if the Gemini API key is configured."""
    return bool(API_KEY and API_KEY.strip())


def get_client() -> genai.Client | None:
    """Get the active Gemini client or create a new one with configured timeout."""
    global client
    if client is not None:
        return client
    if is_api_configured():
        try:
            http_opts = types.HttpOptions(timeout=DEFAULT_TIMEOUT_MS)
            client = genai.Client(api_key=API_KEY, http_options=http_opts)
            return client
        except Exception:
            return None
    return None

