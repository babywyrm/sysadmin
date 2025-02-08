from flask import Flask, request, jsonify, abort
import jwt  # PyJWT
import os,sys,re

app = Flask(__name__)

  ##
## load your public key from a secure location or environment variable.
##

  PUBLIC_KEY = os.environ.get("JWT_PUBLIC_KEY", """
-----BEGIN PUBLIC KEY-----
YOUR_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
""")

# Expected values for validation; adjust these as needed.
EXPECTED_ISSUER = "https://your-idp.com"
EXPECTED_AUDIENCE = "your-api"

@app.route("/check", methods=["GET", "POST", "OPTIONS"])
def check_auth():
    # Handle preflight requests (if necessary)
    if request.method == "OPTIONS":
        return '', 200

    auth_header = request.headers.get("authorization")
    if not auth_header:
        abort(401, description="Missing Authorization header")

    # Assume token comes as "Bearer <token>"
    try:
        token = auth_header.split(" ")[1]
    except IndexError:
        abort(401, description="Malformed Authorization header")

    try:
        # Decode and verify the JWT
        decoded = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
        )
    except Exception as e:
        abort(401, description=f"Invalid token: {str(e)}")

    # Get the allowed origins from the token (this should be a list of origins)
    allowed_origins = decoded.get("allowed_origins", [])
    origin = request.headers.get("origin", "")

    if origin not in allowed_origins:
        abort(403, description="Origin not allowed")

    # If all checks pass, return a 200 OK response.
    return jsonify({"message": "Authorized"}), 200

if __name__ == "__main__":
    # Listen on port 3000 as specified in our Ambassador AuthService configuration.
    app.run(host="0.0.0.0", port=3000)

##
##
                              
