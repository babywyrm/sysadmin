

# OWASP Top 10 Vulnerabilities for Python/Flask Microservices  (Beta, '24-'25)
**Expanded examples & multiple remediation approaches per category**

---

## 1. Injection (SQL, NoSQL, Command Injection)

### Examples

1. **SQL Injection (SQLite)**
   ```python
   @app.route('/search')
   def search():
       term = request.args.get('q')
       conn = sqlite3.connect('app.db')
       cur = conn.cursor()
       cur.execute(f"SELECT * FROM items WHERE name LIKE '%{term}%'")
       return jsonify(cur.fetchall())
   ```
2. **NoSQL Injection (MongoDB)**
   ```python
   @app.route('/find')
   def find():
       username = request.args.get('user')
       doc = mongo.db.users.find_one({"username": username})
       return jsonify(doc)
   # If attacker passes ?user[$ne]=, they bypass the filter.
   ```
3. **Command Injection**
   ```python
   @app.route('/ping')
   def ping():
       host = request.args.get('host')
       # vulnerable: shell=True
       result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
       return result
   ```

### Remediations

- **ORM / Parameterized Queries**  
  ```python
  user = User.query.filter_by(username=term).all()  # Flask‑SQLAlchemy
  ```
- **Strict Query Building for Mongo**  
  ```python
  from bson import Regex
  username = request.args.get('user', '')
  regex = Regex(f"^{re.escape(username)}$")
  doc = mongo.db.users.find_one({"username": regex})
  ```
- **Safe Command Execution**  
  ```python
  import shlex
  cmd = ["ping", "-c", "1", host]
  result = subprocess.check_output(cmd)  # shell=False
  ```
- **Input Validation Libraries**  
  - **Marshmallow**: schemas to validate/deserialize input  
  - **Cerberus**: lightweight validation  
  - **wtforms**: form field validators  

---

## 2. Broken Authentication

### Examples

1. **Plaintext Password Comparison**
   ```python
   if form.password.data == user.password:
       login_user(user)
   ```
2. **Missing Rate Limiting**
   ```python
   @app.route('/login', methods=['POST'])
   def login():
       # no rate‑limit → brute‑force
   ```
3. **Long‑Lived Tokens**
   ```python
   @app.route('/token')
   def token():
       expires = datetime.timedelta(days=365)
       return create_access_token(identity=user.id, expires_delta=expires)
   ```

### Remediations

- **Hashed Passwords (bcrypt/Argon2)**
  ```python
  from werkzeug.security import generate_password_hash, check_password_hash
  hashed = generate_password_hash(password)  
  check_password_hash(hashed, password)
  ```
- **Flask‑Login + Flask‑Limiter**
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app)
  @limiter.limit("5 per minute")
  @app.route('/login', methods=['POST'])
  def login(): ...
  ```
- **Short‑Lived JWTs & Refresh Tokens**  
  ```python
  create_access_token(..., expires_delta=timedelta(minutes=15))
  create_refresh_token(...)
  ```
- **Libraries**  
  - **Flask‑Login** (session management)  
  - **Flask‑Limiter** (rate limiting)  
  - **Flask‑JWT‑Extended** (JWT with refresh)  

---

## 3. Sensitive Data Exposure

### Examples

1. **Logging Secrets**
   ```python
   app.logger.info(f"DB password: {app.config['DB_PASS']}")
   ```
2. **Hard‑coded API Keys**
   ```python
   API_KEY = "supersecret123"
   ```
3. **Unencrypted Cookies**
   ```python
   resp = make_response("ok")
   resp.set_cookie('token', token)  # no Secure/HttpOnly flags
   ```

### Remediations

- **Environment Variables & python‑decouple**
  ```python
  from decouple import config
  DB_PASS = config('DB_PASS')
  ```
- **Use Vault (hvac) or AWS Secrets Manager**
  ```python
  import hvac
  client = hvac.Client()
  secret = client.secrets.kv.v2.read_secret_version(path='app/db')
  ```
- **Secure Cookies & HSTS (Flask‑Talisman)**
  ```python
  from flask_talisman import Talisman
  Talisman(app, strict_transport_security=True)
  ```
- **Libraries**  
  - **python‑decouple** (env)  
  - **hvac** (HashiCorp Vault)  
  - **Flask‑Talisman** (HTTPS, CSP, HSTS)  

---

## 4. XML External Entities (XXE)

### Examples

1. **xml.etree.ElementTree**
   ```python
   ET.fromstring(xml_data)  # unsafe
   ```
2. **lxml with default settings**
   ```python
   from lxml import etree
   etree.fromstring(xml_data)
   ```
3. **defusedxml partial use**
   ```python
   import defusedxml.minidom as md
   md.parseString(xml_data)
   ```

### Remediations

- **defusedxml Entirely**
  ```python
  from defusedxml.ElementTree import fromstring
  fromstring(xml_data)
  ```
- **Disable DTDs in lxml**
  ```python
  parser = etree.XMLParser(resolve_entities=False, no_network=True)
  etree.fromstring(xml_data, parser)
  ```
- **JSON Instead of XML**  
  ```python
  import json
  data = json.loads(request.data)
  ```
- **Libraries**  
  - **defusedxml**  
  - **lxml** (with secure flags)  

---

## 5. Broken Access Control

### Examples

1. **Unprotected Admin Route**
   ```python
   @app.route('/admin')
   def admin(): ...
   ```
2. **IDOR**
   ```python
   @app.route('/order/<int:id>')
   def order(id):
       return jsonify(get_order(id))  # no user check
   ```
3. **Privilege Escalation via JSON Body**
   ```json
   { "role": "admin" }
   ```

### Remediations

- **Flask‑Login @login_required + Role Check**
  ```python
  @login_required
  @roles_required('admin')
  def admin(): ...
  ```
- **Flask‑Principal for Roles**
  ```python
  from flask_principal import Permission, RoleNeed
  admin_perm = Permission(RoleNeed('admin'))
  @app.route('/admin')
  @login_required
  @admin_perm.require(403)
  def admin(): ...
  ```
- **Object‑Level Checks**
  ```python
  def get_order(id):
      order = Order.query.get(id)
      if order.user_id != current_user.id:
          abort(403)
      return order
  ```
- **Libraries**  
  - **Flask‑Login**  
  - **Flask‑Principal**  
  - **Flask‑User** (roles/permissions)  

---

## 6. Security Misconfiguration

### Examples

1. **DEBUG=True** in production
2. **Exposed Werkzeug debugger**  
   ```python
   app.run(debug=True)
   ```
3. **Default CORS (“*”)**  
   ```python
   CORS(app, resources={r"*": {"origins": "*"}})
   ```

### Remediations

- **Config via Flask‑Env / Config Classes**
  ```python
  app.config.from_object('config.ProductionConfig')
  ```
- **Disable Debug & Secure CORS**
  ```python
  app.run(debug=False)
  from flask_cors import CORS
  CORS(app, resources={r"/api/*": {"origins": "https://your.domain"}})
  ```
- **Helmet‑like Headers (Flask‑Talisman)**
  ```python
  Talisman(app, content_security_policy={"default-src": ["'self'"]})
  ```
- **Libraries**  
  - **Flask‑Env**  
  - **Flask‑Talisman**  
  - **Flask‑CORS**  

---

## 7. Cross‑Site Scripting (XSS)

### Examples

1. **Unsafe Jinja Rendering**
   ```python
   return render_template_string("<p>{{ name }}</p>", name=name)
   ```
2. **Manual string concat in response**
   ```python
   return f"<h1>{request.args['msg']}</h1>"
   ```
3. **InnerHTML in client‑side JS** injecting unescaped data

### Remediations

- **Jinja2 Auto‑escaping**
  ```html
  {{ name }}
  ```
- **Bleach Clean**
  ```python
  from bleach import clean
  safe = clean(user_input)
  ```
- **CSP via Flask‑Talisman**
  ```python
  Talisman(app, content_security_policy="default-src 'self'; script-src 'self'")
  ```
- **Libraries**  
  - **Jinja2** (auto‑escape)  
  - **bleach** (sanitize)  
  - **Flask‑Talisman** (CSP)  

---

## 8. Insecure Deserialization

### Examples

1. **pickle.loads(user_data)**
2. **yaml.load(request.data)**
3. **marshal.loads**

### Remediations

- **Use JSON & itsdangerous**
  ```python
  from itsdangerous import URLSafeSerializer
  s = URLSafeSerializer(app.secret_key)
  data = s.loads(request.data)
  ```
- **Safe YAML**
  ```python
  import yaml
  data = yaml.safe_load(request.data)
  ```
- **Schema Validation**
  ```python
  from marshmallow import Schema, fields
  class ItemSchema(Schema):
      name = fields.Str(required=True)
  data = ItemSchema().loads(request.data)
  ```
- **Libraries**  
  - **itsdangerous**  
  - **PyYAML** (safe_load)  
  - **Marshmallow**  

---

## 9. Using Components with Known Vulnerabilities

### Examples

1. **Outdated Flask v0.12**  
2. **Vulnerable dependencies in requirements.txt**  
3. **Unpinned transitive deps**

### Remediations

- **Regular Audits**  
  ```bash
  pip-audit
  safety check
  ```
- **Pipfile / Poetry lock** to pin versions  
- **Automate with Dependabot** on GitHub  
- **Libraries/Tools**  
  - **pip-audit**  
  - **safety**  
  - **bandit** (code security linter)  

---

## 10. Insufficient Logging & Monitoring

### Examples

1. **No logs on failed auth**  
2. **Generic error handlers hiding issues**  
3. **No request IDs**  

### Remediations

- **Structured Logging (structlog)**
  ```python
  import structlog
  log = structlog.get_logger()
  log = log.bind(request_id=uuid4())
  ```
- **Add Request IDs (Flask‑Request‑ID)**
  ```python
  from flask_request_id import RequestID
  RequestID(app)
  ```
- **Centralize to ELK / Splunk / Graylog**
- **Libraries**  
  - **structlog**  
  - **Flask‑Request‑ID**  
  - **watchtower** (AWS CloudWatch)  

---

