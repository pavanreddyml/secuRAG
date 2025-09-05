# ----------------------------------IMPORTS----------------------------------
import os
from .ollama_client import OllamaClient

# ----------------------------CREATE EXECUTOR HERE----------------------------
class AIResponse:
    def __init__(self):
        self.client = OllamaClient(
            host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "gemma2:2b"),
            download_model=os.getenv("OLLAMA_DOWNLOAD_MODEL", "true") == "true"
        )
        self.system_prompt = os.getenv("OLLAMA_SYSTEM_PROMPT", "You are a helpful assistant.")

    def run(self, **kwargs) -> str:
        kwargs["system_prompt"] = self.system_prompt
        return self.client.get_response(**kwargs)

# -------------------------------DO NOT CHANGE--------------------------------
ai_response = AIResponse()
