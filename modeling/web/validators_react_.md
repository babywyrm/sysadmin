# Input Validation Precheck Checklist for React Applications (v4)  
**Enterprise-grade React validation strategies with code examples & remediation libraries**

> **Purpose:**  
> Implement robust client-side validation in React to prevent invalid data submission and provide immediate user feedback.

---

## 1. Data Schema & Type Enforcement  
**Ensure strong typing and schema validation for forms and API data.**  

- **Formik + Yup**
  ```jsx
  import { Formik, Form, Field } from 'formik';
  import * as Yup from 'yup';

  const UserSchema = Yup.object().shape({
    username: Yup.string()
      .min(3, 'Too short')
      .max(50, 'Too long')
      .required('Required'),
    email: Yup.string()
      .email('Invalid email')
      .required('Required'),
    age: Yup.number()
      .integer('Must be an integer')
      .min(18, 'Must be at least 18')
      .max(120, 'Must be realistic')
      .required('Required'),
    website: Yup.string()
      .url('Must be a valid URL')
  });

  function UserForm() {
    return (
      <Formik
        initialValues={{ username: '', email: '', age: '', website: '' }}
        validationSchema={UserSchema}
        onSubmit={values => {
          // Submit validated data
        }}
      >
        {({ errors, touched }) => (
          <Form>
            <Field name="username" />
            {errors.username && touched.username && <div>{errors.username}</div>}
            
            <Field name="email" type="email" />
            {errors.email && touched.email && <div>{errors.email}</div>}
            
            <Field name="age" type="number" />
            {errors.age && touched.age && <div>{errors.age}</div>}
            
            <Field name="website" />
            {errors.website && touched.website && <div>{errors.website}</div>}
            
            <button type="submit">Submit</button>
          </Form>
        )}
      </Formik>
    );
  }
  ```
  - **OWASP**: [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)  
  - **Libs**: `formik`, `yup`, `joi`, `zod`

- **React Hook Form + Zod**
  ```jsx
  import { useForm } from 'react-hook-form';
  import { zodResolver } from '@hookform/resolvers/zod';
  import { z } from 'zod';

  const userSchema = z.object({
    username: z.string().min(3).max(50),
    email: z.string().email(),
    age: z.number().int().min(18).max(120),
    website: z.string().url().optional().or(z.literal(''))
  });

  function UserForm() {
    const { 
      register, 
      handleSubmit, 
      formState: { errors } 
    } = useForm({
      resolver: zodResolver(userSchema)
    });
    
    const onSubmit = data => console.log(data);
    
    return (
      <form onSubmit={handleSubmit(onSubmit)}>
        <input {...register('username')} />
        {errors.username && <p>{errors.username.message}</p>}
        
        <input {...register('email')} type="email" />
        {errors.email && <p>{errors.email.message}</p>}
        
        <input {...register('age', { valueAsNumber: true })} type="number" />
        {errors.age && <p>{errors.age.message}</p>}
        
        <input {...register('website')} placeholder="Website (optional)" />
        {errors.website && <p>{errors.website.message}</p>}
        
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```
  - **Libs**: `react-hook-form`, `zod`, `@hookform/resolvers`

---

## 2. Length, Range & Boundary Checks  
**Prevent excessive data and validate numeric boundaries.**

- **Custom Length Validation Hook**
  ```jsx
  import { useState, useCallback } from 'react';

  function useInputValidation(initialValue = '', config = {}) {
    const { 
      maxLength = Infinity, 
      minLength = 0,
      required = false 
    } = config;
    
    const [value, setValue] = useState(initialValue);
    const [error, setError] = useState('');
    
    const validate = useCallback(() => {
      if (required && value.trim() === '') {
        setError('This field is required');
        return false;
      }
      
      if (value.length < minLength) {
        setError(`Must be at least ${minLength} characters`);
        return false;
      }
      
      if (value.length > maxLength) {
        setError(`Cannot exceed ${maxLength} characters`);
        return false;
      }
      
      setError('');
      return true;
    }, [value, maxLength, minLength, required]);
    
    const onChange = (e) => {
      const newValue = e.target.value;
      setValue(newValue);
      
      // Optional: Clear error when typing
      if (error) setError('');
    };
    
    return { value, onChange, error, validate };
  }

  // Usage in component
  function CommentForm() {
    const comment = useInputValidation('', {
      minLength: 10,
      maxLength: 500,
      required: true
    });
    
    const handleSubmit = (e) => {
      e.preventDefault();
      if (comment.validate()) {
        // Submit comment
      }
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <textarea 
            value={comment.value}
            onChange={comment.onChange}
            onBlur={comment.validate}
          />
          <div className="length-indicator">
            {comment.value.length}/500
          </div>
          {comment.error && (
            <div className="error">{comment.error}</div>
          )}
        </div>
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```

- **File Size Validation**
  ```jsx
  import { useState } from 'react';

  function FileUpload() {
    const [file, setFile] = useState(null);
    const [error, setError] = useState('');
    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
    
    const handleFileChange = (e) => {
      const selectedFile = e.target.files[0];
      setError('');
      
      if (!selectedFile) return;
      
      if (selectedFile.size > MAX_FILE_SIZE) {
        setError(`File too large. Maximum size is ${MAX_FILE_SIZE / (1024 * 1024)}MB`);
        e.target.value = null; // Reset input
        return;
      }
      
      setFile(selectedFile);
    };
    
    return (
      <div>
        <input 
          type="file" 
          accept=".jpg,.jpeg,.png,.pdf" 
          onChange={handleFileChange} 
        />
        {error && <div className="error">{error}</div>}
        {file && <div>Selected: {file.name}</div>}
      </div>
    );
  }
  ```
  
---

## 3. Pattern & Format Validation  
**Enforce strict formats for common data types.**

- **Regular Expression Validation**
  ```jsx
  import { useState } from 'react';

  // Reusable validation patterns
  const PATTERNS = {
    // US phone format: (123) 456-7890 or 123-456-7890
    PHONE: /^(\(\d{3}\)|\d{3})[-\s]?\d{3}[-\s]?\d{4}$/,
    // Credit card number: 16 digits, optional spaces/dashes
    CREDIT_CARD: /^(\d{4}[-\s]?){3}\d{4}$/,
    // Strong password: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    // ZIP code: 5 digits or 5+4 format
    ZIP: /^\d{5}([-]\d{4})?$/,
    // UUID v4
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  };

  function PatternInput({ 
    label, 
    pattern, 
    errorMessage, 
    onChange,
    type = 'text',
    required = false 
  }) {
    const [value, setValue] = useState('');
    const [error, setError] = useState('');
    
    const handleChange = (e) => {
      const newValue = e.target.value;
      setValue(newValue);
      
      // Clear error while typing
      if (error) setError('');
      
      if (onChange) onChange(newValue);
    };
    
    const handleBlur = () => {
      if (required && !value) {
        setError(`${label} is required`);
        return;
      }
      
      if (value && !pattern.test(value)) {
        setError(errorMessage);
        return;
      }
      
      setError('');
    };
    
    return (
      <div className="form-group">
        <label>{label}</label>
        <input
          type={type}
          value={value}
          onChange={handleChange}
          onBlur={handleBlur}
          required={required}
        />
        {error && <div className="error">{error}</div>}
      </div>
    );
  }

  // Usage
  function UserInfoForm() {
    return (
      <form onSubmit={(e) => e.preventDefault()}>
        <PatternInput
          label="Phone Number"
          pattern={PATTERNS.PHONE}
          errorMessage="Please enter a valid phone number"
          required
        />
        
        <PatternInput
          label="Credit Card"
          pattern={PATTERNS.CREDIT_CARD}
          errorMessage="Please enter a valid 16-digit card number"
          required
        />
        
        <PatternInput
          label="Password"
          type="password"
          pattern={PATTERNS.PASSWORD}
          errorMessage="Password must be at least 8 characters with uppercase, lowercase, number and special character"
          required
        />
        
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```

- **Date Format & Range Validation**
  ```jsx
  import { useState } from 'react';

  function DateRangeValidator() {
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [error, setError] = useState('');
    
    const validateDateRange = () => {
      if (!startDate || !endDate) {
        setError('Both start and end dates are required');
        return false;
      }
      
      const start = new Date(startDate);
      const end = new Date(endDate);
      const today = new Date();
      
      // Check if dates are valid
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        setError('Please enter valid dates');
        return false;
      }
      
      // Check if start date is in the past
      if (start > today) {
        setError('Start date cannot be in the future');
        return false;
      }
      
      // Check if end date is after start date
      if (end < start) {
        setError('End date must be after start date');
        return false;
      }
      
      // Check if range is within allowed limit (e.g., 1 year)
      const oneYear = 365 * 24 * 60 * 60 * 1000;
      if (end.getTime() - start.getTime() > oneYear) {
        setError('Date range cannot exceed 1 year');
        return false;
      }
      
      setError('');
      return true;
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      if (validateDateRange()) {
        // Process valid date range
        console.log('Valid date range:', { startDate, endDate });
      }
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="startDate">Start Date:</label>
          <input
            id="startDate"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
        </div>
        
        <div>
          <label htmlFor="endDate">End Date:</label>
          <input
            id="endDate"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>
        
        {error && <div className="error">{error}</div>}
        
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```
  - **Libs**: `date-fns`, `luxon`, `moment`

---

## 4. Allow-List vs Deny-List  
**Always favor validating against known good patterns.**

- **Dropdown with Strict Options**
  ```jsx
  import { useState } from 'react';

  function RoleSelector() {
    // Define strict allow-list of roles
    const ALLOWED_ROLES = [
      { id: 'admin', label: 'Administrator' },
      { id: 'editor', label: 'Editor' },
      { id: 'viewer', label: 'Viewer' },
      { id: 'guest', label: 'Guest' }
    ];
    
    const [selectedRole, setSelectedRole] = useState('');
    const [error, setError] = useState('');
    
    const handleChange = (e) => {
      const selected = e.target.value;
      
      // Validate against allow-list (defensive programming)
      const isValidRole = ALLOWED_ROLES.some(role => role.id === selected);
      
      if (!isValidRole && selected !== '') {
        setError('Invalid role selected');
        return;
      }
      
      setSelectedRole(selected);
      setError('');
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      if (!selectedRole) {
        setError('Please select a role');
        return;
      }
      
      // Double-check against allow-list before submission
      const isValidRole = ALLOWED_ROLES.some(role => role.id === selectedRole);
      if (!isValidRole) {
        setError('Invalid role selected');
        return;
      }
      
      // Process valid selection
      console.log('Selected role:', selectedRole);
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="role">User Role:</label>
          <select
            id="role"
            value={selectedRole}
            onChange={handleChange}
            required
          >
            <option value="">-- Select Role --</option>
            {ALLOWED_ROLES.map(role => (
              <option key={role.id} value={role.id}>
                {role.label}
              </option>
            ))}
          </select>
          {error && <div className="error">{error}</div>}
        </div>
        
        <button type="submit">Save Role</button>
      </form>
    );
  }
  ```

- **Strict Value Selection with Radio Buttons**
  ```jsx
  import { useState } from 'react';

  function PaymentMethodSelector() {
    // Define allow-list of payment methods
    const PAYMENT_METHODS = [
      { id: 'credit', label: 'Credit Card' },
      { id: 'debit', label: 'Debit Card' },
      { id: 'paypal', label: 'PayPal' },
      { id: 'bank', label: 'Bank Transfer' }
    ];
    
    const [selectedMethod, setSelectedMethod] = useState('');
    const [error, setError] = useState('');
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      if (!selectedMethod) {
        setError('Please select a payment method');
        return;
      }
      
      // Validate against allow-list
      const isValidMethod = PAYMENT_METHODS.some(
        method => method.id === selectedMethod
      );
      
      if (!isValidMethod) {
        setError('Invalid payment method');
        return;
      }
      
      // Process valid selection
      console.log('Selected payment method:', selectedMethod);
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <h3>Select Payment Method</h3>
          
          {PAYMENT_METHODS.map(method => (
            <div key={method.id} className="radio-option">
              <input
                type="radio"
                id={method.id}
                name="paymentMethod"
                value={method.id}
                checked={selectedMethod === method.id}
                onChange={(e) => {
                  setSelectedMethod(e.target.value);
                  setError('');
                }}
              />
              <label htmlFor={method.id}>{method.label}</label>
            </div>
          ))}
          
          {error && <div className="error">{error}</div>}
        </div>
        
        <button type="submit">Continue</button>
      </form>
    );
  }
  ```

---

## 5. Canonicalization & Normalization  
**Standardize inputs to prevent evasion techniques.**

- **URL Normalization**
  ```jsx
  import { useState } from 'react';

  function LinkValidator() {
    const [url, setUrl] = useState('');
    const [error, setError] = useState('');
    
    const normalizeAndValidateUrl = (inputUrl) => {
      try {
        // Try to construct a URL object (throws if invalid)
        let normalizedUrl = new URL(inputUrl);
        
        // Force HTTPS protocol
        if (normalizedUrl.protocol !== 'https:') {
          normalizedUrl = new URL(`https://${normalizedUrl.hostname}${normalizedUrl.pathname}${normalizedUrl.search}`);
        }
        
        // Check against allow-list of domains
        const allowedDomains = ['example.com', 'mysite.org', 'trusted-site.net'];
        const hostname = normalizedUrl.hostname;
        
        const isAllowedDomain = allowedDomains.some(domain => 
          hostname === domain || hostname.endsWith(`.${domain}`)
        );
        
        if (!isAllowedDomain) {
          return { valid: false, error: 'Domain not allowed' };
        }
        
        return {
          valid: true,
          normalizedUrl: normalizedUrl.toString()
        };
      } catch (error) {
        return { valid: false, error: 'Invalid URL format' };
      }
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      setError('');
      
      if (!url.trim()) {
        setError('URL is required');
        return;
      }
      
      const result = normalizeAndValidateUrl(url);
      
      if (!result.valid) {
        setError(result.error);
        return;
      }
      
      // Process the normalized URL
      console.log('Normalized URL:', result.normalizedUrl);
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="url">Website URL:</label>
          <input
            id="url"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />
          {error && <div className="error">{error}</div>}
        </div>
        
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```

- **Unicode Normalization**
  ```jsx
  import { useState } from 'react';

  function UsernameInput() {
    const [username, setUsername] = useState('');
    const [error, setError] = useState('');
    
    const normalizeAndValidateUsername = (input) => {
      // Skip empty inputs
      if (!input) return { valid: false, error: 'Username is required' };
      
      // Normalize Unicode to NFC form
      const normalized = input.normalize('NFKC');
      
      // Check for homograph attacks (mixed scripts)
      const latinChars = /[a-z]/i;
      const cyrillicChars = /[\u0400-\u04FF]/;
      const mixedScripts = latinChars.test(normalized) && cyrillicChars.test(normalized);
      
      if (mixedScripts) {
        return { valid: false, error: 'Username contains mixed scripts' };
      }
      
      // Validate against allowed pattern
      const validPattern = /^[a-zA-Z0-9_-]{3,20}$/;
      if (!validPattern.test(normalized)) {
        return {
          valid: false,
          error: 'Username must be 3-20 characters and contain only letters, numbers, underscores or hyphens'
        };
      }
      
      return { valid: true, normalizedValue: normalized };
    };
    
    const handleChange = (e) => {
      const input = e.target.value;
      setUsername(input);
      
      // Clear error while typing
      if (error) setError('');
    };
    
    const handleBlur = () => {
      const result = normalizeAndValidateUsername(username);
      
      if (!result.valid) {
        setError(result.error);
      } else if (result.normalizedValue !== username) {
        // Update with normalized value
        setUsername(result.normalizedValue);
      }
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      const result = normalizeAndValidateUsername(username);
      
      if (!result.valid) {
        setError(result.error);
        return;
      }
      
      // Process the normalized username
      console.log('Normalized username:', result.normalizedValue);
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="username">Username:</label>
          <input
            id="username"
            value={username}
            onChange={handleChange}
            onBlur={handleBlur}
            placeholder="Enter username"
          />
          {error && <div className="error">{error}</div>}
        </div>
        
        <button type="submit">Submit</button>
      </form>
    );
  }
  ```
  - **Libs**: `unorm`

---

## 6. Contextual Escaping & Encoding  
**Use proper escaping per context to prevent XSS.**

- **DOMPurify for HTML Sanitization**
  ```jsx
  import { useState } from 'react';
  import DOMPurify from 'dompurify';

  function ContentDisplay({ htmlContent }) {
    // Configure DOMPurify
    const sanitizeConfig = {
      ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br'],
      ALLOWED_ATTR: ['href', 'target', 'rel'],
      FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input'],
      ADD_ATTR: ['target'], // Allow target="_blank"
      FORCE_BODY: true,     // Wrap in <body> if needed
      USE_PROFILES: { html: true }
    };
    
    // Sanitize HTML
    const sanitizedContent = DOMPurify.sanitize(htmlContent, sanitizeConfig);
    
    return (
      <div className="content-display">
        <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
      </div>
    );
  }

  function RichTextEditor() {
    const [content, setContent] = useState('');
    
    const handleContentChange = (e) => {
      setContent(e.target.value);
    };
    
    return (
      <div className="rich-text-editor">
        <h3>Editor</h3>
        <textarea
          value={content}
          onChange={handleContentChange}
          rows={6}
          placeholder="Enter HTML content (limited tags allowed)"
        />
        
        <h3>Preview (Sanitized)</h3>
        <ContentDisplay htmlContent={content} />
      </div>
    );
  }
  ```
  - **OWASP**: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
  - **Libs**: `dompurify`, `html-react-parser`, `react-sanitized-html`

- **Safe JSON Handling**
  ```jsx
  import { useState, useEffect } from 'react';

  function SafeJsonRenderer() {
    const [jsonData, setJsonData] = useState(null);
    const [error, setError] = useState('');
    
    // Simulate fetching data from an API
    useEffect(() => {
      const fetchData = async () => {
        try {
          const response = await fetch('/api/data');
          
          if (!response.ok) {
            throw new Error('Failed to fetch data');
          }
          
          // Safely parse JSON
          const text = await response.text();
          
          try {
            // Parse in a try-catch block
            const data = JSON.parse(text);
            setJsonData(data);
          } catch (parseError) {
            throw new Error('Invalid JSON response');
          }
        } catch (error) {
          setError(error.message);
        }
      };
      
      fetchData();
    }, []);
    
    // Safe JSON stringification for display
    const safeStringify = (obj) => {
      try {
        return JSON.stringify(
          obj,
          (key, value) => {
            // Handle special cases or potentially dangerous values
            if (value && typeof value === 'object') {
              // Create a safe copy without functions or prototype methods
              return Object.keys(value).reduce((result, key) => {
                // Skip functions and __proto__
                if (typeof value[key] !== 'function' && key !== '__proto__') {
                  result[key] = value[key];
                }
                return result;
              }, {});
            }
            return value;
          },
          2
        );
      } catch (error) {
        return '{"error": "Could not stringify object"}';
      }
    };
    
    if (error) {
      return <div className="error">Error: {error}</div>;
    }
    
    return (
      <div className="json-viewer">
        <h3>JSON Data</h3>
        <pre>
          {jsonData ? safeStringify(jsonData) : 'Loading...'}
        </pre>
      </div>
    );
  }
  ```

---

## 7. File Upload & Content Validation  
**Thoroughly validate uploaded files.**

- **File Type and Size Validation**
  ```jsx
  import { useState } from 'react';

  function SecureFileUpload() {
    const [file, setFile] = useState(null);
    const [preview, setPreview] = useState(null);
    const [error, setError] = useState('');
    
    // Configuration
    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
    const ALLOWED_TYPES = {
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png'],
      'application/pdf': ['.pdf']
    };
    
    // Extract file extension
    const getFileExtension = (filename) => {
      return filename.slice(((filename.lastIndexOf('.') - 1) >>> 0) + 1).toLowerCase();
    };
    
    const validateFile = (file) => {
      // Check if file exists
      if (!file) return { valid: false, error: 'No file selected' };
      
      // Check file size
      if (file.size > MAX_FILE_SIZE) {
        return {
          valid: false,
          error: `File too large. Maximum size is ${MAX_FILE_SIZE / (1024 * 1024)}MB`
        };
      }
      
      // Check file type
      const fileType = file.type;
      const extension = `.${getFileExtension(file.name)}`;
      
      if (!Object.keys(ALLOWED_TYPES).includes(fileType)) {
        return {
          valid: false,
          error: 'Unsupported file type'
        };
      }
      
      // Verify extension matches content type
      if (!ALLOWED_TYPES[fileType].includes(extension)) {
        return {
          valid: false,
          error: 'File extension does not match file type'
        };
      }
      
      return { valid: true };
    };
    
    const handleFileChange = (e) => {
      const selectedFile = e.target.files[0];
      setError('');
      setPreview(null);
      
      if (!selectedFile) {
        setFile(null);
        return;
      }
      
      const validation = validateFile(selectedFile);
      
      if (!validation.valid) {
        setError(validation.error);
        e.target.value = null; // Reset input
        setFile(null);
        return;
      }
      
      setFile(selectedFile);
      
      // Generate preview for images
      if (selectedFile.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (e) => setPreview(e.target.result);
        reader.readAsDataURL(selectedFile);
      }
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      if (!file) {
        setError('Please select a file');
        return;
      }
      
      // Re-validate before submission
      const validation = validateFile(file);
      
      if (!validation.valid) {
        setError(validation.error);
        return;
      }
      
      // Create FormData for submission
      const formData = new FormData();
      formData.append('file', file);
      
      // Submit to server
      console.log('Uploading file:', file.name);
      // API call would go here
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="file">Select File:</label>
          <input
            id="file"
            type="file"
            onChange={handleFileChange}
            accept={Object.entries(ALLOWED_TYPES)
              .flatMap(([type, exts]) => exts)
              .join(',')}
          />
          
          {error && <div className="error">{error}</div>}
          
          {file && !error && (
            <div className="file-info">
              <p>Name: {file.name}</p>
              <p>Size: {(file.size / 1024).toFixed(2)} KB</p>
              <p>Type: {file.type}</p>
            </div>
          )}
          
          {preview && (
            <div className="preview">
              <img src={preview} alt="Preview" style={{ maxWidth: '200px' }} />
            </div>
          )}
        </div>
        
        <button type="submit" disabled={!file || error}>Upload</button>
      </form>
    );
  }
  ```
  - **Libs**: `react-dropzone`, `file-type`

---

## 8. Schema Validation for API Responses  
**Validate incoming API data before processing.**

- **API Response Validation with Zod**
  ```jsx
  import { useState, useEffect } from 'react';
  import { z } from 'zod';

  // Define schema for API response
  const UserSchema = z.object({
    id: z.string().uuid(),
    name: z.string().min(1),
    email: z.string().email(),
    role: z.enum(['admin', 'user', 'guest']),
    created: z.string().datetime(),
    lastLogin: z.string().datetime().nullable(),
    settings: z.object({
      theme: z.enum(['light', 'dark', 'system']).default('system'),
      notifications: z.boolean().default(true)
    })
  });

  const UsersListSchema = z.array(UserSchema);

  function UsersList() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    
    useEffect(() => {
      const fetchUsers = async () => {
        try {
          setLoading(true);
          const response = await fetch('/api/users');
          
          if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
          }
          
          const data = await response.json();
          
          // Validate API response against schema
          try {
            const validatedData = UsersListSchema.parse(data);
            setUsers(validatedData);
          } catch (validationError) {
            console.error('API response validation failed:', validationError);
            setError('Received invalid data from API');
          }
        } catch (error) {
          setError(error.message);
        } finally {
          setLoading(false);
        }
      };
      
      fetchUsers();
    }, []);
    
    if (loading) return <div>Loading...</div>;
    if (error) return <div className="error">Error: {error}</div>;
    
    return (
      <div className="users-list">
        <h2>Users</h2>
        <ul>
          {users.map(user => (
            <li key={user.id}>
              <strong>{user.name}</strong> ({user.email}) - {user.role}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  ```
  - **Libs**: `zod`, `yup`, `joi`, `ajv`

---

## 9. Cross-Field Validation  
**Implement validations spanning multiple fields.**

- **Form with Cross-Field Validation**
  ```jsx
  import { useState } from 'react';

  function PasswordResetForm() {
    const [formData, setFormData] = useState({
      password: '',
      confirmPassword: '',
      securityAnswer: ''
    });
    
    const [errors, setErrors] = useState({});
    
    const handleChange = (e) => {
      const { name, value } = e.target;
      
      setFormData({
        ...formData,
        [name]: value
      });
      
      // Clear errors when typing
      if (errors[name]) {
        setErrors({
          ...errors,
          [name]: undefined
        });
      }
    };
    
    const validateForm = () => {
      const newErrors = {};
      
      // Password strength validation
      if (!formData.password) {
        newErrors.password = 'Password is required';
      } else if (formData.password.length < 8) {
        newErrors.password = 'Password must be at least 8 characters';
      } else if (!/(?=.*[A-Z])/.test(formData.password)) {
        newErrors.password = 'Password must contain at least one uppercase letter';
      } else if (!/(?=.*[a-z])/.test(formData.password)) {
        newErrors.password = 'Password must contain at least one lowercase letter';
      } else if (!/(?=.*\d)/.test(formData.password)) {
        newErrors.password = 'Password must contain at least one number';
      } else if (!/(?=.*[@$!%*?&])/.test(formData.password)) {
        newErrors.password = 'Password must contain at least one special character';
      }
      
      // Cross-field validation: Confirm password must match
      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
      }
      
      // Security answer validation
      if (!formData.securityAnswer) {
        newErrors.securityAnswer = 'Security answer is required';
      } else if (formData.securityAnswer.toLowerCase() === formData.password.toLowerCase()) {
        // Cross-field validation: Security answer should not be the same as password
        newErrors.securityAnswer = 'Security answer cannot be the same as your password';
      }
      
      setErrors(newErrors);
      return Object.keys(newErrors).length === 0;
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      if (validateForm()) {
        // Form is valid, process submission
        console.log('Form submitted successfully');
      }
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="password">New Password:</label>
          <input
            id="password"
            name="password"
            type="password"
            value={formData.password}
            onChange={handleChange}
          />
          {errors.password && <div className="error">{errors.password}</div>}
        </div>
        
        <div>
          <label htmlFor="confirmPassword">Confirm Password:</label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleChange}
          />
          {errors.confirmPassword && <div className="error">{errors.confirmPassword}</div>}
        </div>
        
        <div>
          <label htmlFor="securityAnswer">Security Answer:</label>
          <input
            id="securityAnswer"
            name="securityAnswer"
            type="text"
            value={formData.securityAnswer}
            onChange={handleChange}
            placeholder="Your first pet's name"
          />
          {errors.securityAnswer && <div className="error">{errors.securityAnswer}</div>}
        </div>
        
        <button type="submit">Reset Password</button>
      </form>
    );
  }
  ```

---

## 10. Logging & Monitoring Validation Failures  
**Track patterns of validation failures for security insights.**

- **Form with Validation Logging**
  ```jsx
  import { useState } from 'react';

  // Mock logging service
  const logService = {
    logValidationFailure: (component, field, value, error) => {
      console.warn(
        `Validation failure in ${component}: ` +
        `field "${field}" with value "${value}" - ${error}`
      );
      
      // In production, send to server or analytics
      // fetch('/api/logs/validation', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({
      //     component, field, error,
      //     // Don't log actual value in production
      //     timestamp: new Date().toISOString()
      //   })
      // });
    }
  };

  function LoginForm() {
    const [credentials, setCredentials] = useState({
      email: '',
      password: ''
    });
    
    const [errors, setErrors] = useState({});
    const [submitAttempts, setSubmitAttempts] = useState(0);
    
    const handleChange = (e) => {
      const { name, value } = e.target;
      
      setCredentials({
        ...credentials,
        [name]: value
      });
      
      // Clear errors when typing
      if (errors[name]) {
        setErrors({
          ...errors,
          [name]: undefined
        });
      }
    };
    
    const validateForm = () => {
      const newErrors = {};
      
      // Email validation
      if (!credentials.email) {
        newErrors.email = 'Email is required';
      } else if (!/\S+@\S+\.\S+/.test(credentials.email)) {
        newErrors.email = 'Email is invalid';
        // Log validation failure
        logService.logValidationFailure(
          'LoginForm',
          'email',
          credentials.email,
          'Invalid email format'
        );
      }
      
      // Password validation
      if (!credentials.password) {
        newErrors.password = 'Password is required';
      } else if (credentials.password.length < 8) {
        newErrors.password = 'Password must be at least 8 characters';
        // Log validation failure
        logService.logValidationFailure(
          'LoginForm',
          'password',
          '[REDACTED]', // Don't log actual password
          'Password too short'
        );
      }
      
      setErrors(newErrors);
      return Object.keys(newErrors).length === 0;
    };
    
    const handleSubmit = (e) => {
      e.preventDefault();
      
      setSubmitAttempts(prev => prev + 1);
      
      if (validateForm()) {
        // Form is valid, attempt login
        console.log('Login attempt with:', credentials.email);
      } else {
        // Log multiple failed attempts
        if (submitAttempts >= 2) {
          logService.logValidationFailure(
            'LoginForm',
            'multiple_attempts',
            credentials.email,
            `${submitAttempts + 1} failed validation attempts`
          );
        }
      }
    };
    
    return (
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="email">Email:</label>
          <input
            id="email"
            name="email"
            type="email"
            value={credentials.email}
            onChange={handleChange}
          />
          {errors.email && <div className="error">{errors.email}</div>}
        </div>
        
        <div>
          <label htmlFor="password">Password:</label>
          <input
            id="password"
            name="password"
            type="password"
            value={credentials.password}
            onChange={handleChange}
          />
          {errors.password && <div className="error">{errors.password}</div>}
        </div>
        
        <button type="submit">Log In</button>
      </form>
    );
  }
  ```
  - **Libs**: `sentry`, `logrocket`

---

## React Validation Libraries Summary

| Library | Description | Best For |
|---------|-------------|----------|
| Formik | Form state management with validation | Complete form solutions |
| Yup | Schema validation library | Schema-based validation |
| Zod | TypeScript-first schema validation | Type-safe validations |
| react-hook-form | Performant form library | High-performance forms |
| validator.js | String validation utilities | Individual field validation |
| DOMPurify | HTML sanitization | User-generated content |
| react-dropzone | File upload with validation | File upload interfaces |
| ajv | JSON Schema validator | API request/response validation |
| date-fns | Date utility library | Date validation and manipulation |
| react-query | Data fetching with validation | API integration |
