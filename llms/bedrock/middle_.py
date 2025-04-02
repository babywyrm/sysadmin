import requests
import json
from typing import Dict, Any, Optional

class BedrockClient:
    def __init__(self, api_base_url: str, api_key: Optional[str] = None):
        self.api_base_url = api_base_url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json"
        }
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
    
    def generate_text(
        self,
        prompt: str,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        max_tokens: int = 1024,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """Generate text using the guardrailed Bedrock API"""
        endpoint = f"{self.api_base_url}/api/generate"
        
        payload = {
            "prompt": prompt,
            "model_id": model_id,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=30
            )
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            print(f"Error calling Bedrock API: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                print(f"Response: {e.response.text}")
            raise
