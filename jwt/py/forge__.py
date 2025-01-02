import jwt
import datetime

# Shared HMAC secret key (replace with your actual key securely)
HMAC_SECRET = "example_shared_secret_key"

def reforge_token():
    print("--- Token Reforging Tool ---")

    # Input original token
    original_token = input("Enter the original token: ").strip()

    try:
        # Decode the token without verification to extract the payload
        decoded_token = jwt.decode(original_token, HMAC_SECRET, algorithms=["HS256"], options={"verify_signature": False})
        print("Decoded token payload:")
        print(decoded_token)
    except jwt.InvalidTokenError as e:
        print(f"Error: Invalid token. {e}")
        return

    # Modify the issuer (iss) field
    new_issuer = input("Enter the new issuer (e.g., https://example.com/realms/new-realm): ").strip()
    decoded_token["iss"] = new_issuer

    # Add or expand scopes
    current_scope = decoded_token.get("scope", "")
    print(f"Current scope: {current_scope}")
    additional_scopes = input("Enter additional scopes (space-separated, e.g., read write admin): ").strip()
    updated_scope = f"{current_scope} {additional_scopes}".strip()
    decoded_token["scope"] = " ".join(sorted(set(updated_scope.split())))  # Remove duplicates and sort

    # Update the audience (aud) field
    current_aud = decoded_token.get("aud", [])
    if isinstance(current_aud, str):
        current_aud = [current_aud]
    print(f"Current audience(s): {current_aud}")
    additional_aud = input("Enter additional audiences (comma-separated, e.g., fleet-api,warbird-api): ").strip()
    if additional_aud:
        updated_aud = current_aud + [aud.strip() for aud in additional_aud.split(",")]
        decoded_token["aud"] = list(sorted(set(updated_aud)))  # Remove duplicates and sort

    # Add or modify other claims
    while True:
        add_claim = input("Do you want to add or modify another claim? (yes/no): ").strip().lower()
        if add_claim == "no":
            break
        claim_key = input("Enter the claim key: ").strip()
        claim_value = input("Enter the claim value: ").strip()
        decoded_token[claim_key] = claim_value

    # Update expiration (optional)
    try:
        exp_in_minutes = int(input("Enter token expiration time in minutes (default: 60): ") or 60)
        decoded_token["exp"] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_in_minutes)).timestamp())
    except ValueError:
        print("Invalid expiration time. Using default of 60 minutes.")
        decoded_token["exp"] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=60)).timestamp())

    # Re-sign the token
    reforged_token = jwt.encode(decoded_token, HMAC_SECRET, algorithm="HS256")

    print("\n--- Reforged Token ---")
    print(reforged_token)
    print("\nUse this token to authenticate with the updated claims.")

if __name__ == "__main__":
    reforge_token()
