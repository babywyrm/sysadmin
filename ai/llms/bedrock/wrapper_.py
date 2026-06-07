import json
from flask import Flask, request, jsonify
from bedrock_guardrails import BedrockGuardrails

app = Flask(__name__)

# Initialize guardrails with configuration
guardrails = BedrockGuardrails(
    max_tokens=2048,
    rate_limit=20,
    allowed_models=[
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0"
    ],
)

@app.route("/api/generate", methods=["POST"])
def generate_text():
    try:
        data = request.json
        
        # Extract parameters
        prompt = data.get("prompt")
        model_id = data.get("model_id", "anthropic.claude-3-sonnet-20240229-v1:0")
        max_tokens = data.get("max_tokens", 1024)
        temperature = data.get("temperature", 0.7)
        
        # Apply guardrails and invoke model
        response = guardrails.invoke_model(
            prompt=prompt,
            model_id=model_id,
            max_tokens=max_tokens,
            temperature=temperature
        )
        
        return jsonify({"success": True, "data": response})
    
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    except Exception as e:
        app.logger.error(f"Error processing request: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
