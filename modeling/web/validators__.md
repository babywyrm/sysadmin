

# Input Validation Precheck Checklist for Threat Modeling (v3.1)

**Enterprise‑grade, framework‑agnostic guidance with OWASP references, code examples & remediation libraries**

> **Purpose:**  
> Prior to threat modeling, validate **all** user‑controlled inputs through a defense‑in‑depth strategy. This involves leveraging layered validators including checks for schema, syntax, semantics, normalization, encoding, and context‑aware sanitation. Special attention is given to modern frameworks — React, Angular, and Vue on the frontend and Python/Flask and Java/Spring on the backend.

---

## 1. Data Schema & Type Enforcement  
### Overview  
Enforce a strict contract at your system’s boundary. This guards against malformed or deliberately malicious input. Whether using declarative validations or code-based type enforcement, consistency is key.

### Backend Examples  
#### Java / Spring  
Utilize JSR‑380 annotations and OpenAPI documentation to ensure data integrity:

```java
import javax.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

public class CreateUserRequest {
    @NotNull
    @Size(min = 3, max = 30)
    public String username;

    @NotNull
    @Email
    public String email;

    @NotNull
    @Min(18)
    @Max(120)
    public Integer age;
}

@Operation(summary = "Create user", 
    requestBody = @RequestBody(required = true,
    content = @Content(schema = @Schema(implementation = CreateUserRequest.class))))
@PostMapping("/users")
public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest req) {
    // Business logic here
    …
}
```

- **OWASP Reference:**  
  [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)  
- **Libraries:** Hibernate Validator, `springdoc-openapi-ui`

#### Python / Flask  
Use Pydantic or Marshmallow for schema enforcement:

```python
from pydantic import BaseModel, Field, EmailStr, conint
from flask import request, Flask, abort

app = Flask(__name__)

class UserModel(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    age: conint(ge=18, le=120)

@app.route('/users', methods=['POST'])
def create_user():
    try:
        user = UserModel(**request.get_json())
    except Exception as e:
        abort(400, description=str(e))
    # Process user data here
    …
```

- **OWASP Note:**  
  Always enforce whitelist schemas.
- **Libraries:** `pydantic`, `marshmallow`

### Frontend Examples  
For React, Angular, and Vue, client-side type-checking is valuable both for UX and preliminary validation.

#### React / Angular / Vue  
- **React Example with Yup / Formik:**

```jsx
import React from 'react';
import { useFormik } from 'formik';
import * as Yup from 'yup';

const validationSchema = Yup.object({
  username: Yup.string().min(3).max(30).required(),
  email: Yup.string().email().required(),
  age: Yup.number().min(18).max(120).required(),
});

const CreateUserForm = () => {
  const formik = useFormik({
    initialValues: { username: '', email: '', age: '' },
    validationSchema,
    onSubmit: values => {
      // Submit values to backend API
    },
  });

  return (
    <form onSubmit={formik.handleSubmit}>
      <input
        name="username"
        value={formik.values.username}
        onChange={formik.handleChange}
        placeholder="Username"
      />
      <input
        name="email"
        type="email"
        value={formik.values.email}
        onChange={formik.handleChange}
        placeholder="Email"
      />
      <input
        name="age"
        type="number"
        value={formik.values.age}
        onChange={formik.handleChange}
        placeholder="Age"
      />
      <button type="submit">Submit</button>
    </form>
  );
};

export default CreateUserForm;
```

- **Angular Example with Reactive Forms:**

```ts
import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';

@Component({
  selector: 'app-create-user',
  template: `
    <form [formGroup]="userForm" (ngSubmit)="onSubmit()">
      <input formControlName="username" placeholder="Username" />
      <input formControlName="email" type="email" placeholder="Email" />
      <input formControlName="age" type="number" placeholder="Age" />
      <button type="submit" [disabled]="userForm.invalid">Submit</button>
    </form>
  `,
})
export class CreateUserComponent implements OnInit {
  userForm!: FormGroup;
  constructor(private fb: FormBuilder) {}

  ngOnInit() {
    this.userForm = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(30)]],
      email: ['', [Validators.required, Validators.email]],
      age: ['', [Validators.required, Validators.min(18), Validators.max(120)]],
    });
  }

  onSubmit() {
    if (this.userForm.valid) {
      // Process form data
    }
  }
}
```

- **Vue Example with Vuelidate:**

```html
<template>
  <form @submit.prevent="onSubmit">
    <input v-model="user.username" placeholder="Username" />
    <input v-model="user.email" placeholder="Email" type="email" />
    <input v-model="user.age" placeholder="Age" type="number" />
    <button type="submit">Submit</button>
  </form>
</template>

<script>
import { required, minLength, maxLength, email, between } from 'vuelidate/lib/validators';
export default {
  data() {
    return {
      user: {
        username: '',
        email: '',
        age: null,
      },
    };
  },
  validations: {
    user: {
      username: { required, minLength: minLength(3), maxLength: maxLength(30) },
      email: { required, email },
      age: { required, between: between(18, 120) },
    },
  },
  methods: {
    onSubmit() {
      this.$v.$touch();
      if (!this.$v.$invalid) {
        // Submit data to backend
      }
    },
  },
};
</script>
```

---

## 2. Length, Range & Boundary Checks  
### Overview  
These checks ensure that inputs do not lead to issues such as buffer overflows, denial-of-service (DoS) attacks, or excessive resource consumption.

### Backend Examples  
#### Java / Spring  
```java
public class CommentRequest {
    @Size(max = 10000)
    public String comment;
}

// Validating a request parameter
@GetMapping("/order")
public ResponseEntity<?> processOrder(@RequestParam @Max(100) Integer quantity) {
    // Process order
    …
}
```

#### Python / Flask  
Limit the payload size early in the request lifecycle:

```python
from flask import request, abort, Flask

app = Flask(__name__)

@app.before_request
def limit_payload():
    if request.content_length and request.content_length > 1_000_000:  # 1 MB
        abort(413, description="Payload too large")
```

#### gRPC  
When using gRPC, specify maximum message size via server options:

```java
// Pseudo-code for Java gRPC server
Server server = ServerBuilder.forPort(8080)
    .maxInboundMessageSize(1024 * 1024)  // 1MB limit
    .build();
```

### Frontend Examples  
For HTML5 and JavaScript-based validations:
  
#### HTML5  
```html
<input type="text" maxlength="100" minlength="3" />
<input type="number" min="1" max="100" />
```

#### Using validator.js  
```js
import validator from 'validator';
const isValidUsername = validator.isLength(str, { min: 3, max: 30 });
```

---

## 3. Pattern & Format Validation  
### Overview  
Enforce that input data conforms to specific formats such as UUIDs, emails, or dates to prevent injection and format-related attacks.

### Backend Examples  
#### Java  
```java
@Pattern(regexp = "^[0-9a-fA-F\\-]{36}$", message = "Invalid UUID format")
public String uuid;
```

#### Python / Flask  
```python
import re
from flask import abort

UUID_RE = re.compile(r"^[0-9a-fA-F\-]{36}$")

def validate_uuid(uuid):
    if not UUID_RE.match(uuid):
        abort(400, description="Invalid UUID format")
```

### Frontend Examples  
#### HTML5  
```html
<input type="email" />
<input type="date" />
```

#### Using Yup in React or Angular  
```js
email: Yup.string().email("Please provide a valid email").required()
```

#### AJV for JSON Schema in Vue or Node.js  
```js
const schema = {
  type: 'object',
  properties: {
    email: { type: 'string', format: 'email' }
  },
  required: ['email']
};
```

---

## 4. Allow‑List vs Deny‑List  
### Overview  
Favor using allow‑lists (whitelists) that contain known, good values over deny‑lists. This reduces unexpected behavior by accepting only the valid inputs.

### Backend Examples  
#### Java / Spring  
```java
List<String> roles = List.of("USER", "ADMIN", "MOD");
if (!roles.contains(req.getRole())) {
    throw new BadRequestException("Invalid role provided");
}
```

#### Python / Flask  
```python
ALLOWED_ROLES = {'user', 'admin', 'mod'}
if role not in ALLOWED_ROLES:
    abort(400, description="Invalid role provided")
```

### Frontend Examples  
#### HTML Select Input  
```html
<select required>
  <option value="user">User</option>
  <option value="admin">Admin</option>
  <option value="mod">Moderator</option>
</select>
```

#### Yup Example in React/Angular  
```js
role: Yup.string()
  .oneOf(['user', 'admin', 'mod'], "Invalid role selected")
  .required()
```

---

## 5. Canonicalization & Normalization  
### Overview  
Ensure that inputs are normalized or canonicalized in order to mitigate attacks such as Unicode obfuscation, path traversal, and homograph attacks.

### Backend Examples  
#### Java  
```java
import java.text.Normalizer;
import java.nio.file.Path;
import java.nio.file.Paths;

String norm = Normalizer.normalize(input, Normalizer.Form.NFKC);
Path p = Paths.get(baseDir, norm).normalize();
if (!p.startsWith(baseDir)) {
    throw new SecurityException("Invalid file path");
}
```

#### Python / Flask  
```python
import unicodedata
import os
from flask import abort

def secure_filename(filename, base_dir):
    norm_name = unicodedata.normalize('NFC', filename)
    path = os.path.normpath(os.path.join(base_dir, norm_name))
    if not path.startswith(os.path.abspath(base_dir)):
        abort(400, description="Invalid path")
    return path
```

### Frontend Examples  
#### Using unorm in JavaScript  
```js
import unorm from 'unorm';
const normalizedInput = unorm.nfc(userInput);
```

---

## 6. Contextual Escaping & Encoding  
### Overview  
Proper escaping and encoding prevents injection attacks. Always apply context‑specific escaping for HTML, JavaScript, URL, and SQL.

### Backend Examples  
#### Java / Thymeleaf (auto‑escaping)  
```html
<p th:text="${userInput}"></p>
```

#### Python / Flask with Jinja2  
```html
<!doctype html>
<html>
  <head><title>Sample Template</title></head>
  <body>
    <p>{{ userInput }}</p>
  </body>
</html>
```

### Frontend Examples  
#### Using DOMPurify in any JavaScript framework  
```js
import DOMPurify from 'dompurify';
const cleanHTML = DOMPurify.sanitize(dirtyHTML);
```

#### Angular DomSanitizer  
```ts
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

sanitizeHtml(dirtyHtml: string) {
  return this.sanitizer.bypassSecurityTrustHtml(dirtyHtml);
}
```

---

## 7. File Upload & Content Validation  
### Overview  
File uploads pose unique risks. Always use allow‑lists for MIME types, verify file signatures via magic bytes, and scan for malware.

### Backend Examples  
#### Python / Flask  
```python
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'pdf'}
UPLOAD_FOLDER = '/secure/uploads'

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    if not allowed_file(f.filename):
        abort(400, description="File type not allowed")
    filename = secure_filename(f.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(file_path)
    # Optionally perform malware scan here
    return "File uploaded successfully"
```

#### Additional Malware Scanning  
```python
import clamd
cd = clamd.ClamdNetworkSocket()
# Use the file stream to scan for malware
scan_result = cd.scan_stream(file.read())
if scan_result:
    abort(400, description="Malware detected")
```

### Frontend Examples  
#### HTML Input Restriction  
```html
<input type="file" accept=".png,.jpg,.pdf" />
```

#### FilePond Example  
```js
import FilePond from 'filepond';
import FilePondPluginFileValidateType from 'filepond-plugin-file-validate-type';

FilePond.registerPlugin(FilePondPluginFileValidateType);
const pond = FilePond.create(document.querySelector('input[type="file"]'), {
  acceptedFileTypes: ['image/png', 'image/jpeg', 'application/pdf']
});
```

#### file-type Library (Node.js / Browser)  
```js
import fileType from 'file-type';

async function validateFile(blob) {
  const type = await fileType.fromBlob(blob);
  if (!type || !(['image/png', 'application/pdf'].includes(type.mime))) {
    throw new Error('File type not allowed');
  }
}
```

---

## 8. JSON/XML Parsing Hardening  
### Overview  
Avoid vulnerabilities by rejecting unknown fields, disabling dangerous features such as DTD processing in XML, and using hardened parsers.

### Backend Examples  
#### Python / Flask using Marshmallow  
```python
from marshmallow import Schema, fields, EXCLUDE

class UserSchema(Schema):
    username = fields.String(required=True)
    email = fields.Email(required=True)
    age = fields.Integer(required=True)

    class Meta:
        unknown = EXCLUDE   # Reject any unknown fields

# Use the schema to load data
data, errors = UserSchema().load(data)
if errors:
    abort(400, description=str(errors))
```

#### XML Parsing with defusedxml  
```python
from defusedxml.ElementTree import fromstring

def parse_xml(xml_data):
    try:
        tree = fromstring(xml_data)
    except Exception:
        abort(400, description="Invalid XML")
    return tree
```

### Frontend Examples  
#### AJV for JSON Schema Enforcement  
```js
import Ajv from 'ajv';
const ajv = new Ajv({ allErrors: true, removeAdditional: 'all' });
const valid = ajv.validate(schema, data);
if (!valid) {
  console.error(ajv.errors);
}
```

#### GraphQL Context  
- Use libraries like `graphql-shield` for permissions  
- Use custom scalars (e.g., via `graphql-scalars`) for strict type enforcement

---

## 9. Business Logic & Semantic Checks  
### Overview  
Validation is not just about format; business rules and semantic validations are critical. This includes cross-field validations, ownership checks, and enforcing resource quotas.

### Backend Examples  
#### Python / Flask with Marshmallow Cross‑Field Validations  
```python
from marshmallow import validates_schema, ValidationError

class EventSchema(Schema):
    start = fields.DateTime(required=True)
    end = fields.DateTime(required=True)

    @validates_schema
    def check_dates(self, data, **kwargs):
        if data['end'] <= data['start']:
            raise ValidationError("End time must be after start time")
```

#### Ownership Verification Example  
```python
def validate_order_access(order, current_user):
    if order.user_id != current_user.id:
        abort(403, description="Access forbidden: You cannot modify this order")
```

### Frontend Examples  
#### Yup Cross‑Field Validation Example  
```js
const validationSchema = Yup.object().shape({
  startDate: Yup.date().required(),
  endDate: Yup.date()
    .min(Yup.ref('startDate'), "End date must be after start date")
    .required(),
});
```

#### Angular Custom Validator  
```ts
import { AbstractControl, ValidationErrors } from '@angular/forms';

export function endAfterStart(control: AbstractControl): ValidationErrors | null {
  const start = control.get('startDate')?.value;
  const end = control.get('endDate')?.value;
  return end > start ? null : { dateError: 'End date must be after start date' };
}
```

---

## 10. Logging, Monitoring & Alerting  
### Overview  
Record validation failures along with anomalous patterns or repeated offenses. This can help in both debugging and identifying potential attack vectors.

### Backend Examples  
#### Python with structlog  
```python
import structlog
from uuid import uuid4

log = structlog.get_logger().bind(request_id=str(uuid4()))
log.warning("Validation failure", field="email")
```

#### Integrating with Sentry  
```python
import sentry_sdk
import os

sentry_sdk.init(dsn=os.getenv("SENTRY_DSN"))
# Capture a warning or exception as needed
try:
    # code that may fail validation
    pass
except Exception as e:
    sentry_sdk.capture_exception(e)
```

### Frontend Examples  
#### Sentry in JavaScript (React/Angular/Vue)  
```js
import * as Sentry from '@sentry/browser';

Sentry.init({ dsn: process.env.SENTRY_DSN });
Sentry.captureMessage("Form validation errors", "warning");
```

#### Session Replay Tools  
Consider using tools like LogRocket or FullStory to capture session replays and logs, which can help with debugging complex frontend interactions and validation issues.

---

## 11. Additional Considerations  
### GraphQL  
- **Validation:**  
  Leverage input validation via **graphql-request** and custom scalars.
- **OWASP Reference:**  
  [GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Security_Cheat_Sheet.html)

### gRPC  
- **Validation:**  
  Use Protobuf v3 with **protoc-gen-validate** to enforce message constraints during serialization.

### WebSockets/Socket.io  
- Validate every event payload using JSON schema validators; reuse the same validation libraries as REST endpoints for consistency.

### API Gateways (AWS, Kong, Ambassador)  
- **Built‑in Validators:**  
  Use request validation and schema enforcement at the gateway level to prevent malformed traffic from hitting backend services.

### Mobile Platforms  
- **Android:**  
  Implement InputFilters and leverage Kotlin’s serialization libraries for type-checking.
- **iOS:**  
  Use libraries such as SwiftValidator or JSON schema-based frameworks to perform early validation on user inputs.


##
##
