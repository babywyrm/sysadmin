
# Input Validation Precheck Checklist for Threat Modeling (v3)  
**Enterprise‑grade, framework‑agnostic guidance with OWASP references, code examples & remediation libraries**

> **Purpose:**  
> Before threat modeling, verify **all** user‑controlled inputs via layered validators—schema, syntax, semantics, normalization, encoding, and context‑aware checks.

---

## 1. Data Schema & Type Enforcement  
**Ensure strict contract enforcement at the boundary.**  

### Backend

- **Java/Spring (JSR‑380 + Springdoc OpenAPI)**
  ```java
  public class CreateUserRequest {
      @NotNull @Size(min=3, max=30)       public String username;
      @NotNull @Email                     public String email;
      @NotNull @Min(18) @Max(120)         public Integer age;
  }
  @Operation(summary="Create user", 
    requestBody=@RequestBody(required=true,
      content=@Content(schema=@Schema(implementation=CreateUserRequest.class))))
  @PostMapping("/users")
  public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest req) { … }
  ```
  - **OWASP**: [Data Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)  
  - **Libs**: Hibernate Validator, `springdoc-openapi-ui`

- **Python/Flask (Pydantic + Marshmallow)**
  ```python
  from pydantic import BaseModel, Field, EmailStr, conint
  class UserModel(BaseModel):
      username: str        = Field(..., min_length=3, max_length=30)
      email:    EmailStr
      age:      conint(ge=18, le=120)

  @app.route('/users', methods=['POST'])
  def create_user():
      user = UserModel(**request.get_json())  # raises on invalid
      …
  ```
  - **OWASP**: enforce whitelist schemas  
  - **Libs**: `pydantic`, `marshmallow`

- **Node.js/Express (Express‑Validator + Joi)**
  ```js
  import { body, validationResult } from 'express-validator';
  app.post('/users', [
    body('username').isLength({min:3, max:30}).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('age').isInt({min:18, max:120})
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    …
  });
  ```
  - **Libs**: `express-validator`, `joi`

---

## 2. Length, Range & Boundary Checks  
**Prevent buffer overflows, DoS via resource exhaustion.**

### Backend

- **Spring Boot**  
  ```java
  @Size(max=10000)       public String comment;
  @RequestParam @Max(100) Integer quantity;
  ```
- **Flask**  
  ```python
  @app.before_request
  def limit_payload():
      if request.content_length and request.content_length > 1_000_000:
          abort(413)
  ```
- **gRPC**  
  - Define `max_message_size` in server options to restrict payload.

### Frontend

- **HTML5**  
  ```html
  <input type="text" maxlength="100" minlength="3" />
  <input type="number" min="1" max="100" />
  ```
- **validator.js**  
  ```js
  validator.isLength(str, { min:3, max:30 });
  ```

---

## 3. Pattern & Format Validation  
**Enforce strict formats (UUID, email, ISO date).**

### Backend

- **Java**  
  ```java
  @Pattern(regexp="^[0-9a-fA-F\\-]{36}$")
  public String uuid;
  ```
- **Flask**  
  ```python
  import re
  UUID_RE = re.compile(r"^[0-9a-fA-F\-]{36}$")
  if not UUID_RE.match(uuid): abort(400)
  ```

### Frontend

- **HTML5**  
  ```html
  <input type="email" />
  <input type="date" />
  ```
- **Yup**  
  ```js
  email: Yup.string().email().required()
  ```
- **AJV (JSON Schema)**  
  ```js
  const schema = { type:'object',
    properties:{ email:{ type:'string', format:'email' } },
    required:['email'] };
  ```

---

## 4. Allow‑List vs Deny‑List  
**Always favor allow‑lists of known good values.**

### Backend

- **Spring**  
  ```java
  List<String> roles = List.of("USER","ADMIN","MOD");
  if (!roles.contains(req.getRole())) throw new BadRequest();
  ```
- **Flask**  
  ```python
  ALLOWED = {'user','admin','mod'}
  if role not in ALLOWED: abort(400)
  ```

### Frontend

- **Select Input**  
  ```html
  <select required>
    <option value="user">User</option>
    <option value="admin">Admin</option>
  </select>
  ```
- **Yup**  
  ```js
  role: Yup.string().oneOf(['user','admin','mod']).required()
  ```

---

## 5. Canonicalization & Normalization  
**Prevent Unicode, path traversal, homograph bypasses.**

### Backend

- **Java**  
  ```java
  String norm = Normalizer.normalize(input, Normalizer.Form.NFKC);
  Path p = Paths.get(baseDir, norm).normalize();
  if (!p.startsWith(baseDir)) throw new SecurityException();
  ```
- **Flask**  
  ```python
  import unicodedata, os
  name = unicodedata.normalize('NFC', filename)
  path = os.path.normpath(os.path.join(base_dir, name))
  if not path.startswith(base_dir): abort(400)
  ```

### Frontend

- **unorm (npm)**  
  ```js
  import unorm from 'unorm';
  unorm.nfc(userInput);
  ```

---

## 6. Contextual Escaping & Encoding  
**Escape data per context: HTML, JS, URL, SQL.**

### Backend

- **Thymeleaf** (auto‑escape)  
  ```html
  <p th:text="${userInput}"></p>
  ```
- **Jinja2**  
  ```html
  {{ userInput }}
  ```

### Frontend

- **DOMPurify**  
  ```js
  import DOMPurify from 'dompurify';
  const clean = DOMPurify.sanitize(dirtyHTML);
  ```
- **Angular DomSanitizer**  
  ```ts
  safeHtml = this.sanitizer.bypassSecurityTrustHtml(dirtyHtml);
  ```

---

## 7. File Upload & Content Validation  
**Whitelist MIME, check magic bytes, scan for malware.**

### Backend

- **Flask**  
  ```python
  from werkzeug.utils import secure_filename
  ALLOWED = {'png','jpg','pdf'}
  f = request.files['file']
  ext = f.filename.rsplit('.',1)[1].lower()
  if ext not in ALLOWED: abort(400)
  filename = secure_filename(f.filename)
  f.save(os.path.join(UPLOAD, filename))
  ```
- **Malware Scan**  
  ```python
  import clamd
  cd = clamd.ClamdNetworkSocket()
  cd.scan_stream(file.read())
  ```

### Frontend

- **accept attribute**  
  ```html
  <input type="file" accept=".png,.jpg,.pdf" />
  ```
- **FilePond**  
  ```js
  FilePond.registerPlugin(FilePondPluginFileValidateType);
  FilePond.create(input, { acceptedFileTypes: ['image/png','application/pdf'] });
  ```
- **file-type (npm)**  
  ```js
  import fileType from 'file-type';
  const type = await fileType.fromBlob(blob);
  ```

---

## 8. JSON/XML Parsing Hardening  
**Reject unknown fields, disable DTDs, use safe parsers.**

### Backend

- **Marshmallow**  
  ```python
  UserSchema(unknown=RAISE).load(data)
  ```
- **defusedxml**  
  ```python
  from defusedxml.ElementTree import fromstring
  fromstring(xml_data)
  ```

### Frontend

- **AJV**  
  ```js
  const ajv = new Ajv({ allErrors:true, removeAdditional:'all' });
  const valid = ajv.validate(schema, data);
  ```
- **GraphQL**  
  - **graphql-shield** for schema‑enforced permissions  
  - **graphql-scalars** for strict types  

---

## 9. Business Logic & Semantic Checks  
**Cross‑field, ownership, rate limits, quota enforcement.**

### Backend

- **Flask/Marshmallow**
  ```python
  @validates_schema
  def check_dates(self,data,**_):
      if data['end'] <= data['start']:
          raise ValidationError("end must be after start")
  ```
- **Ownership**  
  ```python
  if order.user_id != current_user.id: abort(403)
  ```

### Frontend

- **Yup Cross‑Field**  
  ```js
  endDate: Yup.date().min(Yup.ref('startDate'), "Must be after start")
  ```
- **Angular Custom Validator**  
  ```ts
  this.form = fb.group({...}, {validators: endAfterStart});
  ```

---

## 10. Logging, Monitoring & Alerting  
**Log validation failures, metrics, anomalous patterns.**

### Backend

- **structlog**  
  ```python
  import structlog
  log = structlog.get_logger().bind(request_id=uuid4())
  log.warning("Validation failure", field="email")
  ```
- **Sentry**  
  ```python
  import sentry_sdk
  sentry_sdk.init(dsn=os.getenv("SENTRY_DSN"))
  ```

### Frontend

- **Sentry**  
  ```js
  Sentry.init({ dsn: process.env.SENTRY_DSN });
  Sentry.captureMessage("Form validation errors", "warning");
  ```
- **LogRocket** / **FullStory** for session replay + logs

---


## Additional Contexts & OWASP References

- **GraphQL**:  
  - Input validation via **graphql-request** + custom scalars  
  - **OWASP**: [GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Security_Cheat_Sheet.html)

- **gRPC**:  
  - Protobuf v3 + **protoc-gen-validate** for message constraints  

- **WebSockets / Socket.io**:  
  - Validate event payloads with same JSON schemas  

- **API Gateway (AWS / Kong / Ambassador)**:  
  - Use built‑in request validators / schema enforcement  

- **Mobile**:  
  - Android InputFilters + Kotlin serialization  
  - iOS SwiftValidator + JSON schema libs  

##
##
