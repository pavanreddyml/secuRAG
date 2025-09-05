import json
from typing import Iterable, Optional, Dict, List
import ollama


class OllamaClient:
    def __init__(self, host: str, model: str, download_model: bool = False):
        self.host = host
        self.model = model
        self.download_model = download_model

    def get_response(
        self,
        prompt: str,
        system_prompt: str = "",
        conversation_history: Optional[Iterable[Dict[str, str]]] = None,
    ) -> Optional[str]:
        try:
            self._download_model()
            conversation_history = conversation_history or []
            client = ollama.Client(host=self.host)

            messages: List[Dict[str, str]] = []
            allowed_roles = {"user", "assistant", "system"}

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            if conversation_history:
                for m in conversation_history:
                    if not isinstance(m, dict):
                        continue
                    role = m.get("role", "user")
                    content = m.get("content", "")
                    if not content:
                        continue
                    if role not in allowed_roles:
                        role = "user"
                    messages.append({"role": role, "content": content})

            messages.append({"role": "user", "content": prompt})

            resp = client.chat(
                model=self.model,
                messages=messages,
                stream=False,
            )
            # print(resp.get("message", {}).get("content"))  # Debug disabled
            return resp.get("message", {}).get("content")
        except Exception as e:
            # print(f"Error getting response from LLM: {str(e)}")  # Debug disabled
            return None

    def _download_model(self):
        client = ollama.Client(host=self.host)
        models = client.list().get("models", [])
        names = [m.get("model") for m in models]

        if not self.download_model:
            return "Model Does Not Exist. Download Model into Ollama Server"
        if self.model not in names:
            for progress in client.pull(self.model, stream=True):
                print(progress)
