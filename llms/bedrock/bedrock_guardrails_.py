import os,sys,re
import time
import logging
import boto3
from typing import Dict, Any, List, Optional
from functools import wraps

class BedrockGuardrails:
    def __init__(
        self,
        max_tokens: int = 4096,
        rate_limit: int = 10,  # requests per minute
        allowed_models: List[str] = None,
        content_filters: List[str] = None,
        logging_enabled: bool = True,
    ):
        self.max_tokens = max_tokens
        self.rate_limit = rate_limit
        self.allowed_models = allowed_models or ["anthropic.claude-3-sonnet-20240229-v1:0"]
        self.content_filters = content_filters or [
            r"(password|secret|credit.?card|ssn)",
            r"(private|sensitive).{0,20}data"
        ]
        self.logging_enabled = logging_enabled
        self.request_timestamps = []
        
        # Initialize Bedrock client
        self.bedrock_runtime = boto3.client(
            service_name="bedrock-runtime",
            region_name="us-east-1"  # Change to your region
        )
        
        # Set up logging
        if logging_enabled:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            self.logger = logging.getLogger("bedrock_guardrails")
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting based on requests per minute"""
        current_time = time.time()
        
        # Remove timestamps older than 60 seconds
        self.request_timestamps = [ts for ts in self.request_timestamps 
                                  if current_time - ts < 60]
        
        if len(self.request_timestamps) >= self.rate_limit:
            sleep_time = 60 - (current_time - self.request_timestamps[0])
            if sleep_time > 0:
                if self.logging_enabled:
                    self.logger.warning(f"Rate limit reached. Waiting {sleep_time:.2f}s")
                time.sleep(sleep_time)
        
        self.request_timestamps.append(time.time())
    
    def _validate_input(self, prompt: str) -> str:
        """Validate and sanitize the input prompt"""
        # Check for empty or too short prompts
        if not prompt or len(prompt.strip()) < 3:
            raise ValueError("Prompt too short or empty")
        
        # Check for potential sensitive information
        for pattern in self.content_filters:
            matches = re.findall(pattern, prompt, re.IGNORECASE)
            if matches:
                censored_prompt = re.sub(
                    pattern, 
                    "[FILTERED]", 
                    prompt, 
                    flags=re.IGNORECASE
                )
                if self.logging_enabled:
                    self.logger.warning(f"Filtered sensitive content in prompt")
                return censored_prompt
        
        return prompt
    
    def _validate_model(self, model_id: str):
        """Validate the requested model is allowed"""
        if model_id not in self.allowed_models:
            raise ValueError(f"Model {model_id} not in allowed models: {self.allowed_models}")
    
    def invoke_model(
        self, 
        prompt: str,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
        **kwargs
    ) -> Dict[str, Any]:
        """Invoke the Bedrock model with guardrails applied"""
        # Apply guardrails
        self._enforce_rate_limit()
        self._validate_model(model_id)
        safe_prompt = self._validate_input(prompt)
        
        # Prepare the request
        request_max_tokens = min(max_tokens or self.max_tokens, self.max_tokens)
        
        # Create appropriate request body based on model provider
        if "anthropic" in model_id:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": request_max_tokens,
                "temperature": temperature,
                "messages": [{"role": "user", "content": safe_prompt}]
            }
        elif "amazon.titan" in model_id:
            request_body = {
                "inputText": safe_prompt,
                "textGenerationConfig": {
                    "maxTokenCount": request_max_tokens,
                    "temperature": temperature,
                }
            }
        else:
            # Default format for other models
            request_body = {
                "prompt": safe_prompt,
                "max_tokens": request_max_tokens,
                "temperature": temperature,
            }
        
        # Add any additional parameters
        request_body.update(kwargs)
        
        # Log the request if enabled
        if self.logging_enabled:
            self.logger.info(f"Invoking {model_id} with {len(safe_prompt)} chars")
        
        try:
            # Make the API call
            response = self.bedrock_runtime.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            # Process the response
            response_body = json.loads(response.get("body").read())
            
            # Log success
            if self.logging_enabled:
                token_count = response.get("contentLength", 0)
                self.logger.info(f"Response received: {token_count} bytes")
            
            return response_body
        
        except Exception as e:
            if self.logging_enabled:
                self.logger.error(f"Error invoking model: {str(e)}")
            raise

##
##

