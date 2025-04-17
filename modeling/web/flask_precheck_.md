```markdown
# OWASP Top 10 Vulnerabilities for Python/Flask Microservices  '25
_Comprehensive examples, whitebox testing steps & open‑source solutions_

---

## 1. Injection (SQL, NoSQL, Command Injection)

### Penetration Testing Steps
1. **Identify inputs** reaching your DB or OS shell (e.g. request.args, form data).  
2. **Inject common payloads**:
   - SQL: `’ OR 1=1--`  
   - NoSQL (Mongo): `{"$ne": null}`  
   - Command: `; ls -la`

### Vulnerable Example: SQL Injection

```python
# app.py
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    # Vulnerable: string concatenation
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    user = cur.fetchone()
    return user or 'Not found'
```

#### Exploit
```
GET /user?username=admin' OR '1'='1
```

### Remediation

```python
# Use SQLAlchemy + parameter binding
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)

@app.route('/user')
def get_user():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    return user.username if user else 'Not found'
```

- **Libraries**:  
  - [Flask‑SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) (ORM, parameterized queries)  
  - [PyMongo](https://pymongo.readthedocs.io/) with query dicts

---

## 2. Broken Authentication

### Penetration Testing Steps
1. **Brute‑force login** with Hydra/Burp Intruder.  
2. **Session fixation**: reuse old session cookies.  
3. **Weak password policies**: test common passwords.

### Vulnerable Example: Plaintext Passwords

```python
# auth.py
from flask import Flask, request, session
app = Flask(__name__)
app.secret_key = 'insecure'

USERS = {'admin': 'secret123'}

@app.route('/login', methods=['POST'])
def login():
    u = request.form['username']
    p = request.form['password']
    if USERS.get(u) == p:
        session['user'] = u
        return 'OK'
    return 'Invalid'
```

### Remediation

```python
# auth_secure.py
from flask import Flask, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required

app = Flask(__name__)
app.secret_key = 'env:SECRET_KEY'

login_manager = LoginManager(app)
# Replace USERS dict with DB-backed, hashed passwords
USERS = {'admin': generate_password_hash('secret123')}

class User(UserMixin):
    def __init__(self, username): self.id = username

@login_manager.user_loader
def load_user(uid): return User(uid) if uid in USERS else None

@app.route('/login', methods=['POST'])
def login():
    u = request.form['username']
    p = request.form['password']
    pw_hash = USERS.get(u)
    if pw_hash and check_password_hash(pw_hash, p):
        login_user(User(u))
        return 'Logged in'
    return 'Invalid', 401

@app.route('/protected')
@login_required
def protected(): return 'Secret data'
```

- **Libraries**:  
  - [Flask‑Login](https://flask-login.readthedocs.io/)  
  - **Werkzeug** security (bcrypt by default)  

---

## 3. Sensitive Data Exposure

### Penetration Testing Steps
1. **Inspect HTTP**: ensure HTTPS enforced.  
2. **Search logs/config** for plaintext secrets.  

### Vulnerable Example: Logging Secrets

```python
# app.py
import logging
logging.basicConfig(level=logging.INFO)
logging.info(f"API key: {app.config['API_KEY']}")
```

### Remediation

```python
# Use environment vars & no logs of secrets
# app.py
from flask import Flask
from flask_talisman import Talisman
import os

app = Flask(__name__)
Talisman(app)  # Enforce HTTPS + secure headers
app.config['API_KEY'] = os.getenv('API_KEY')

# NEVER log app.config['API_KEY']
```

- **Libraries**:  
  - [Flask‑Talisman](https://github.com/GoogleCloudPlatform/flask-talisman) (HTTPS, HSTS, CSP)  
  - [python-dotenv](https://github.com/theskumar/python-dotenv) (env vars)

---

## 4. XML External Entities (XXE)

### Penetration Testing Steps
1. **Find XML endpoints** (e.g. file uploads).  
2. **Send XXE payload**:  
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
   ```
3. **Observe response** leaking `/etc/passwd`.

### Vulnerable Example: Unsafe XML Parsing

```python
# app.py
import xml.etree.ElementTree as ET
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    xml = request.data
    tree = ET.fromstring(xml)  # vulnerable
    return 'OK'
```

### Remediation

```python
# Use defusedxml
from defusedxml.ElementTree import fromstring
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    xml = request.data
    tree = fromstring(xml)  # safe
    return 'OK'
```

- **Libraries**:  
  - [defusedxml](https://pypi.org/project/defusedxml/)  

---

## 5. Broken Access Control

### Penetration Testing Steps
1. **URL tampering**: access `/admin` as non‑admin.  
2. **IDOR**: fetch `/order/123` when logged in as user `456`.

### Vulnerable Example: No Access Checks

```python
# app.py
@app.route('/admin')
def admin():
    return 'ADMIN DASHBOARD'
```

### Remediation

```python
# app.py
from flask_login import login_required, current_user
from functools import wraps

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user.is_authenticated or not current_user.is_admin:
            return 'Forbidden', 403
        return fn(*a, **kw)
    return wrapper

@app.route('/admin')
@login_required
@admin_required
def admin(): return 'ADMIN DASHBOARD'
```

- **Libraries**:  
  - [Flask‑Login](https://flask-login.readthedocs.io/)  
  - [Flask‑Principal](https://pythonhosted.org/Flask-Principal/) (roles)

---

## 6. Security Misconfiguration

### Penetration Testing Steps
1. **Check debug**: `DEBUG=True` in production.  
2. **Inspect default creds**.  

### Vulnerable Example: Debug ON

```python
app = Flask(__name__)
app.config['DEBUG'] = True
```

### Remediation

```python
# config.py
import os
class Config:
    DEBUG = False
    SECRET_KEY = os.getenv('SECRET_KEY')

# app.py
app.config.from_object('config.Config')
```

- **Libraries**:  
  - Flask’s built‑in config & [Flask‑Env](https://pypi.org/project/Flask-Env/)  

---

## 7. Cross‑Site Scripting (XSS)

### Penetration Testing Steps
1. **Inject** `<script>alert(1)</script>` in form fields.  
2. **Inspect** rendered HTML.

### Vulnerable Example: Unsafe Rendering

```python
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return f"<h1>Hello, {name}</h1>"  # No escaping
```

### Remediation

```html
{# templates/greet.html #}
<!doctype html>
<html><body>
  <h1>Hello, <span>{{ name }}</span></h1>
</body></html>
```

```python
# app.py
from flask import render_template
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template('greet.html', name=name)
```

- **Libraries**:  
  - **Jinja2** auto‑escaping  
  - [bleach](https://bleach.readthedocs.io/) (HTML sanitization)

---

## 8. Insecure Deserialization

### Penetration Testing Steps
1. **Locate** endpoints using `pickle.loads`.  
2. **Send** malicious pickle payload to achieve RCE.

### Vulnerable Example: pickle.loads

```python
import pickle
@app.route('/load', methods=['POST'])
def load():
    data = pickle.loads(request.data)  # unsafe
    return 'Loaded'
```

### Remediation

```python
# Use JSON + itsdangerous
from itsdangerous import URLSafeSerializer
serializer = URLSafeSerializer(app.config['SECRET_KEY'])

@app.route('/load', methods=['POST'])
def load():
    data = serializer.loads(request.data)  # Safe signed data
    return 'Loaded'
```

- **Libraries**:  
  - [itsdangerous](https://itsdangerous.palletsprojects.com/)  
  - JSON built‑in

---

## 9. Using Components with Known Vulnerabilities

### Penetration Testing Steps
1. **Run** `pip-audit` or `safety check`.  
2. **Identify** outdated/vulnerable libs.

```bash
pip install pip-audit
pip-audit
```

### Remediation

```bash
pip install --upgrade Flask==2.2.5
```

- **Libraries**:  
  - [pip‑audit](https://github.com/google/pip-audit)  
  - [safety](https://pyup.io/safety/)  

---

## 10. Insufficient Logging & Monitoring

### Penetration Testing Steps
1. **Trigger** failed logins or errors.  
2. **Verify** logs capture these events.

### Vulnerable Example: No Logging

```python
@app.route('/login', methods=['POST'])
def login():
    # …
    pass  # no logs
```

### Remediation

```python
import logging
from flask import request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    success = authenticate(user, request.form['password'])
    if success:
        logger.info(f"User '{user}' logged in")
    else:
        logger.warning(f"Failed login for '{user}'")
    return ('OK' if success else 'Invalid'), (200 if success else 401)
```

- **Libraries**:  
  - **logging** (stdlib)  
  - [Flask‑Logging](https://flask.palletsprojects.com/en/2.2.x/logging/)  
  - External: **Splunk**, **ELK Stack**

---

