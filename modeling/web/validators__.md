

# Input Validation Precheck Checklist for Threat Modeling (v2)  Beta '24-'25
**Expanded with additional libraries, frameworks & code examples (Java, JS, Flask, mobile, GraphQL, gRPC, etc.)**

##
##
##
---

## 1. Data Schema & Type Enforcement

### Backend

- **Java/Spring (Hibernate Validator + Springdoc OpenAPI)**  
  ```java
  public class CreateUserRequest {
      @NotNull @Size(min=3, max=30)       public String username;
      @NotNull @Email                     public String email;
      @NotNull @Min(18) @Max(120)         public Integer age;
  }
  @Operation(requestBody=@RequestBody(required=true, content=@Content(schema=@Schema(implementation=CreateUserRequest.class))))
  @PostMapping("/users")
  public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest req) {…}
  ```
  - **Library**: `springdoc-openapi-ui` auto‑generates schema & validation rules.

- **Python/Flask (Pydantic + Marshmallow)**  
  ```python
  from pydantic import BaseModel, Field, EmailStr, conint

  class UserModel(BaseModel):
      username: str = Field(..., min_length=3, max_length=30)
      email:    EmailStr
      age:      conint(ge=18, le=120)

  @app.route('/users', methods=['POST'])
  def create_user():
      user = UserModel(**request.get_json())  # raises ValidationError
      …
  ```
  - **Library**: `pydantic` for strict parsing & type enforcement.

### Frontend (Web)

- **React**  
  - **React Hook Form + Zod**  
    ```jsx
    import { useForm } from 'react-hook-form';
    import { z } from 'zod';
    import { zodResolver } from '@hookform/resolvers/zod';

    const schema = z.object({
      username: z.string().min(3).max(30),
      email:    z.string().email(),
      age:      z.number().min(18).max(120),
    });

    const { register, handleSubmit, errors } = useForm({
      resolver: zodResolver(schema)
    });
    ```

- **Angular**  
  - **ngx-validate** for declarative validation  
    ```ts
    this.form = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(30)]],
      email:    ['', [Validators.required, Validators.email]],
      age:      ['', [Validators.required, Validators.min(18), Validators.max(120)]]
    });
    ```

- **Vue**  
  - **VeeValidate + Yup**  
    ```js
    import { useForm, useField } from 'vee-validate';
    import * as yup from 'yup';

    const schema = yup.object({
      username: yup.string().min(3).max(30).required(),
      email:    yup.string().email().required(),
      age:      yup.number().min(18).max(120).required(),
    });

    const { handleSubmit } = useForm({ validationSchema: schema });
    ```

- **Svelte**  
  - **svelte-forms-lib + Yup**  
    ```js
    import { createForm } from 'svelte-forms-lib';
    const { form, validate } = createForm({
      initialValues: { username:'', email:'', age:'' },
      validationSchema: yup.object({ /* same as above */ })
    });
    ```

- **Elm**  
  - Elm’s type system enforces schemas at compile time.

### Mobile

- **Android (Kotlin + Validator‑KTX)**  
  ```kotlin
  data class User(
    @Length(min = 3, max = 30) val username: String,
    @Email val email: String,
    @Range(min = 18, max = 120) val age: Int
  )
  ```
  - **Library**: [validator-ktx](https://github.com/valiktor/valiktor)

- **iOS (Swift + SwiftValidator)**  
  ```swift
  let validator = Validator()
  validator.registerField(usernameField, rules: [RequiredRule(), MinLengthRule(length: 3)])
  ```

---

## 2. Length, Range & Boundary Checks

### Backend

- **Java/Spring**  
  ```java
  @Size(max=10000) public String comment;
  @RequestParam @Max(100) Integer quantity;
  ```

- **Flask**  
  ```python
  @app.before_request
  def limit_size():
      if request.content_length and request.content_length>1_000_000:
          abort(413)
  ```

### Frontend

- **HTML5**  
  ```html
  <input type="text" maxlength="100" minlength="3" />
  <input type="number" min="1" max="100" />
  ```

- **Parsley.js**  
  ```html
  <input data-parsley-length="[3, 30]" data-parsley-required />
  ```

- **validator.js**  
  ```js
  import validator from 'validator';
  validator.isLength(str, { min:3, max:30 });
  ```

---

## 3. Pattern & Format Validation

### Backend

- **Java/Spring**  
  ```java
  @Pattern(regexp="^[0-9a-fA-F\\-]{36}$") public String uuid;
  ```

- **Flask**  
  ```python
  if not re.match(r"^[0-9a-fA-F\-]{36}$", uuid): abort(400)
  ```

### Frontend

- **HTML5**  
  ```html
  <input type="email" />
  <input pattern="[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" />
  ```

- **Ajv (JSON Schema)**  
  ```js
  const schema = { type:'string', pattern:'^[0-9a-fA-F\\-]{36}$' };
  ```

---

## 4. Allow‑List vs Deny‑List

### Backend

- **Java**  
  ```java
  if (!Set.of("USER","ADMIN").contains(role)) throw new BadRequest();
  ```

- **Flask**  
  ```python
  allowed={'user','admin'}
  if role not in allowed: abort(400)
  ```

### Frontend

- **HTML Select**  
  ```html
  <select>
    <option value="user">User</option>
    <option value="admin">Admin</option>
  </select>
  ```

- **Yup**  
  ```js
  role: Yup.string().oneOf(['user','admin'])
  ```

---

## 5. Canonicalization & Normalization

### Backend

- **Java**  
  ```java
  String norm=Normalizer.normalize(input,NFKC);
  Path p=Paths.get(base,norm).normalize();
  if(!p.startsWith(base)) throw new SecEx();
  ```

- **Flask**  
  ```python
  n=unicodedata.normalize('NFC',filename)
  p=os.path.normpath(os.path.join(base,n))
  if not p.startswith(base): abort(400)
  ```

### Frontend

- **unorm (npm)**  
  ```js
  import unorm from 'unorm';
  unorm.nfc(userInput);
  ```

---

## 6. Contextual Escaping & Encoding

### Backend

- **Thymeleaf**  
  ```html
  <p th:text="${userInput}"></p>  <!-- auto-escaped -->
  ```

- **Jinja2**  
  ```html
  {{ userInput }}
  ```

### Frontend

- **DOMPurify**  
  ```js
  import DOMPurify from 'dompurify';
  DOMPurify.sanitize(dirtyHTML);
  ```

- **Angular DomSanitizer**  
  ```ts
  this.sanitizer.bypassSecurityTrustHtml(dirty);
  ```

---

## 7. File Upload & Content Validation

### Backend

- **Flask**  
  ```python
  from werkzeug.utils import secure_filename
  ALLOWED={'png','jpg'}
  if ext not in ALLOWED: abort(400)
  ```

- **Malware Scan**  
  ```python
  import clamd; cd=clamd.ClamdUnixSocket(); cd.scan_file(path)
  ```

### Frontend

- **accept attribute**  
  ```html
  <input type="file" accept=".png,.jpg" />
  ```

- **FilePond**  
  ```js
  FilePond.registerPlugin(FilePondPluginFileValidateType);
  ```

---

## 8. JSON/XML Parsing Hardening

### Backend

- **Flask**  
  ```python
  UserSchema(unknown=RAISE).load(obj)
  ```

- **defusedxml**  
  ```python
  from defusedxml.ElementTree import fromstring
  fromstring(xml)
  ```

### Frontend

- **Ajv** (strict mode)  
  ```js
  new Ajv({ allErrors:true, removeAdditional:'all' })
  ```

---

## 9. Business Logic & Semantic Checks

### Backend

- **Flask/Marshmallow**  
  ```python
  @validates_schema
  def check_dates(self,data,**_):
      if data['end']<=data['start']: raise ValidationError()
  ```

### Frontend

- **Yup cross‑field**  
  ```js
  end: Yup.date().min(Yup.ref('start'))
  ```

---

## 10. Logging, Monitoring & Alerting

### Backend

- **structlog**  
  ```python
  import structlog
  log=structlog.get_logger().bind(request_id=uuid4())
  log.info("validation failed", field="email")
  ```

- **Sentry**  
  ```python
  import sentry_sdk; sentry_sdk.init(dsn=…)
  ```

### Frontend

- **Sentry/Bugsnag**  
  ```js
  Sentry.captureMessage("User input validation error");
  ```

---

### Additional Frontend Contexts to Include

- **GraphQL**:  
  - **Apollo Server**: `type Query { user(id: ID!): User }`  
  - **GraphQL Shield** for rule‑based validation  

- **gRPC**:  
  - **Protobuf v3** with `protoc-gen-validate`  

- **WebSockets**:  
  - Validate frames/events with same JSON schema or pydantic  

- **Serverless/API Gateway**:  
  - AWS API Gateway request validators (body/schema)

---

**Usage**:  
1. **Inventory** all APIs/UI/form/file endpoints.  
2. **Map** each to these validators & libraries.  
3. **Automate** tests: contract tests, schema checks.  
4. **Review** exceptions & fallback paths in your threat model.  

By layering backend & frontend (JS/Java/Flask) validation, plus mobile, GraphQL & gRPC, you cover nearly every user‑land entry point before threat modeling.  
```
