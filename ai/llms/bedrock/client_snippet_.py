def main():
    # Initialize client
    client = BedrockClient(api_base_url="http://localhost:5000")
    
    try:
        # Generate text
        response = client.generate_text(
            prompt="Explain quantum computing in simple terms",
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            max_tokens=500,
            temperature=0.7
        )
        
        # Process the response
        if response.get("success"):
            result = response.get("data")
            # Extract the appropriate content based on model
            if "anthropic" in result:
                content = result.get("content")[0].get("text", "")
            else:
                content = result.get("text", "")
            
            print("Generated text:")
            print(content)
        else:
            print(f"Error: {response.get('error')}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
