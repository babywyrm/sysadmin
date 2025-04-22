
# OWASP Top 10 Vulnerabilities for React Applications: Detailed Examples and Solutions (2025, Beta)

##
##


## 1. Cross-Site Scripting (XSS)
### Penetration Testing Steps
**Step 1:** Identify User Inputs: Find places where user data renders in the UI (forms, query parameters, dynamic content).
**Step 2:** Test with XSS Payloads: Try injecting payloads like `<script>alert('XSS')</script>` or `javascript:alert(1)`.

### Example of a Flaw:
```jsx
function UserProfile({ userData }) {
  return (
    <div>
      <h1>Welcome!</h1>
      <div dangerouslySetInnerHTML={{ __html: userData.bio }} />
    </div>
  );
}
```

### Remediation:
**Use React's Built-in XSS Protection:** Avoid `dangerouslySetInnerHTML` and let React automatically escape content.
```jsx
function UserProfile({ userData }) {
  return (
    <div>
      <h1>Welcome!</h1>
      <div>{userData.bio}</div>
    </div>
  );
}
```

**For HTML Content:** Use a dedicated HTML sanitization library.
```jsx
import DOMPurify from "dompurify";

function UserProfile({ userData }) {
  return (
    <div>
      <h1>Welcome!</h1>
      <div
        dangerouslySetInnerHTML={{
          __html: DOMPurify.sanitize(userData.bio),
        }}
      />
    </div>
  );
}
```

### Libraries to Fix:
- DOMPurify (for sanitizing HTML content)
- react-html-parser (with sanitization options)

## 2. Broken Authentication
### Penetration Testing Steps
**Step 1:** Test Token Management: Check how the app handles authentication tokens (JWT, session cookies).
**Step 2:** Check Authentication Flows: Try accessing protected routes directly by URL without login.

### Example of a Flaw:
```jsx
// Storing JWT in localStorage (vulnerable to XSS)
const login = async (username, password) => {
  const response = await api.login(username, password);
  localStorage.setItem("token", response.token);
};

// Using the token
function App() {
  const token = localStorage.getItem("token");
  // Use token for authenticated requests
}
```

### Remediation:
**Use HttpOnly Cookies:** Store tokens in HttpOnly cookies instead of localStorage.
```jsx
// Backend sets HttpOnly cookie
// React doesn't need to handle token storage directly

// For authenticated requests
const api = {
  fetchProtectedData: () => {
    return fetch("/api/protected-data", {
      credentials: "include", // Sends cookies with request
    });
  },
};
```

**Implement Proper Authentication Context:**
```jsx
function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check authentication status on load
    checkAuthStatus().then((status) => {
      setIsAuthenticated(status);
      setLoading(false);
    });
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, setIsAuthenticated, loading }}>
      {children}
    </AuthContext.Provider>
  );
}
```

### Libraries to Fix:
- react-auth-kit
- react-oidc-context
- Auth0 React SDK

## 3. Sensitive Data Exposure
### Penetration Testing Steps
**Step 1:** Inspect Network Traffic: Check if sensitive data is transmitted over unencrypted channels.
**Step 2:** Review Local Storage: Check if sensitive data is stored in browser storage (localStorage, sessionStorage).

### Example of a Flaw:
```jsx
// Storing sensitive user data in localStorage
function saveUserProfile(profile) {
  localStorage.setItem("userProfile", JSON.stringify({
    name: profile.name,
    email: profile.email,
    ssn: profile.ssn, // Sensitive data!
    creditCard: profile.creditCard // Sensitive data!
  }));
}
```

### Remediation:
**Never Store Sensitive Data Client-Side:**
```jsx
// Store only non-sensitive data client-side
function saveUserProfile(profile) {
  localStorage.setItem("userProfile", JSON.stringify({
    name: profile.name,
    email: profile.email,
    // No sensitive data
  }));
}
```

**For Forms with Sensitive Data:**
```jsx
function CreditCardForm() {
  const [cardData, setCardData] = useState({
    number: "",
    cvv: "",
    expiry: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    // Send data directly to server without storing locally
    api.processPayment(cardData).then(() => {
      // Clear form
      setCardData({ number: "", cvv: "", expiry: "" });
    });
  };

  return <form onSubmit={handleSubmit}>...</form>;
}
```

### Libraries to Fix:
- react-hook-form (for secure form handling)
- redux-persist (with blacklisting for sensitive fields)

## 4. Security Misconfiguration
### Penetration Testing Steps
**Step 1:** Check Environment Variables: Look for exposed API keys or secrets in the build.
**Step 2:** Inspect Error Handling: Test if application reveals sensitive error details to users.

### Example of a Flaw:
```jsx
// Hard-coded API key in frontend code
const API_KEY = "sk_live_abcdef123456";

function ApiService() {
  return axios.create({
    headers: { 
      "Authorization": `Bearer ${API_KEY}`
    }
  });
}

// Revealing detailed errors to users
function DataComponent() {
  const [error, setError] = useState(null);
  
  useEffect(() => {
    api.fetchData().catch(error => {
      // Shows raw error to user
      setError(error.toString());
    });
  }, []);
  
  if (error) return <div>{error}</div>;
  return <div>Data loaded</div>;
}
```

### Remediation:
**Use Environment Variables Properly:**
```jsx
// Use environment variables with REACT_APP_ prefix
const apiKey = process.env.REACT_APP_API_KEY;

// Better: Keep secrets on the server
function ApiService() {
  // No API key in frontend code
  return axios.create();
  // Server handles authentication
}
```

**Generic Error Messages:**
```jsx
function DataComponent() {
  const [error, setError] = useState(null);
  
  useEffect(() => {
    api.fetchData().catch(error => {
      // Log actual error for debugging
      console.error(error);
      // Show generic message to user
      setError("An error occurred while loading data");
    });
  }, []);
  
  if (error) return <div>{error}</div>;
  return <div>Data loaded</div>;
}
```

### Libraries to Fix:
- react-error-boundary
- dotenv (for development environment variables)

## 5. Broken Access Control
### Penetration Testing Steps
**Step 1:** Test Role-Based UI: Try accessing admin-only UI components by manipulating routes.
**Step 2:** Test API Access Control: Check if frontend properly enforces authorization on rendered components.

### Example of a Flaw:
```jsx
function App() {
  return (
    <Router>
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/admin" component={AdminPanel} /> {/* No access control! */}
    </Router>
  );
}

// Component showing admin features based only on client-side role
function UserActions({ user }) {
  return (
    <div>
      <button>Edit Profile</button>
      {user.role === "admin" && (
        <button>Delete Users</button> // Client-side role check only
      )}
    </div>
  );
}
```

### Remediation:
**Create Protected Routes:**
```jsx
function ProtectedRoute({ children, role }) {
  const { user, isLoading } = useAuth();
  
  if (isLoading) return <LoadingSpinner />;
  
  if (!user) {
    return <Navigate to="/login" />;
  }
  
  if (role && user.role !== role) {
    return <Navigate to="/unauthorized" />;
  }
  
  return children;
}

function App() {
  return (
    <Router>
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route 
        path="/admin" 
        element={
          <ProtectedRoute role="admin">
            <AdminPanel />
          </ProtectedRoute>
        } 
      />
    </Router>
  );
}
```

**Double-Check Authorization on Backend:**
```jsx
function UserActions({ user }) {
  const deleteUser = async (userId) => {
    try {
      await api.deleteUser(userId);
      // Success handling
    } catch (error) {
      // Handle unauthorized error from backend
      if (error.response?.status === 403) {
        alert("You don't have permission to perform this action");
      }
    }
  };

  return (
    <div>
      <button>Edit Profile</button>
      {user.role === "admin" && (
        <button onClick={() => deleteUser(someId)}>
          Delete Users
        </button>
      )}
    </div>
  );
}
```

### Libraries to Fix:
- react-router (with protected routes)
- casl (for frontend permissions management)

## 6. Using Components with Known Vulnerabilities
### Penetration Testing Steps
**Step 1:** Identify Outdated Dependencies: Use tools like npm audit or Snyk to identify vulnerable packages.
**Step 2:** Test for Exploits: Test older versions of libraries that might have known CVE vulnerabilities.

### Example of a Flaw:
```json
{
  "dependencies": {
    "react": "^17.0.2",
    "react-dom": "^17.0.2",
    "lodash": "^4.14.0", // Vulnerable version with prototype pollution
    "axios": "^0.19.0" // Older version with security issues
  }
}
```

### Remediation:
**Regularly Update Dependencies:**
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lodash": "^4.17.21", // Updated version
    "axios": "^1.6.0" // Updated version
  }
}
```

**Set Up Automated Dependency Scanning:**
```json
{
  "scripts": {
    "audit": "npm audit --production",
    "audit:fix": "npm audit fix",
    "preinstall": "npm audit"
  }
}
```

### Libraries to Fix:
- npm-check-updates
- Snyk
- Dependabot (GitHub)

## 7. Cross-Site Request Forgery (CSRF)
### Penetration Testing Steps
**Step 1:** Identify State-Changing Operations: Find forms and API calls that change data.
**Step 2:** Test CSRF Protection: Try to forge requests from another origin without proper tokens.

### Example of a Flaw:
```jsx
function PasswordChangeForm() {
  const [newPassword, setNewPassword] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    // No CSRF protection
    fetch("/api/change-password", {
      method: "POST",
      body: JSON.stringify({ newPassword }),
      headers: {
        "Content-Type": "application/json",
      },
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />
      <button type="submit">Change Password</button>
    </form>
  );
}
```

### Remediation:
**Use CSRF Tokens:**
```jsx
function PasswordChangeForm() {
  const [newPassword, setNewPassword] = useState("");
  const [csrfToken, setCsrfToken] = useState("");

  useEffect(() => {
    // Fetch CSRF token from the server
    fetch("/api/csrf-token")
      .then((res) => res.json())
      .then((data) => setCsrfToken(data.token));
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    fetch("/api/change-password", {
      method: "POST",
      body: JSON.stringify({ newPassword }),
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      credentials: "include", // Include cookies
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />
      <button type="submit">Change Password</button>
    </form>
  );
}
```

### Libraries to Fix:
- axios (with CSRF token support)
- react-query (with custom request options)

## 8. Insecure Deserialization
### Penetration Testing Steps
**Step 1:** Inspect Data Storage: Look for complex objects stored in localStorage or sessionStorage.
**Step 2:** Test for Prototype Pollution: Try injecting `__proto__` properties into user-controllable objects.

### Example of a Flaw:
```jsx
// Unsafe parsing of JSON from an external source
function loadUserPreferences() {
  const savedPrefs = localStorage.getItem("userPrefs");
  
  if (savedPrefs) {
    // Unsafe deserialization
    const prefs = JSON.parse(savedPrefs);
    applyPreferences(prefs);
  }
}

// Example of prototype pollution vulnerability
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) {
        target[key] = {};
      }
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

### Remediation:
**Validate JSON Structure:**
```jsx
function loadUserPreferences() {
  const savedPrefs = localStorage.getItem("userPrefs");
  
  if (savedPrefs) {
    try {
      const prefs = JSON.parse(savedPrefs);
      
      // Validate the structure before using
      if (!isValidPrefsObject(prefs)) {
        console.error("Invalid preferences format");
        return;
      }
      
      // Use a sanitized copy rather than the original
      const sanitizedPrefs = {
        theme: prefs.theme || "default",
        fontSize: prefs.fontSize || "medium",
        // Only copy expected properties
      };
      
      applyPreferences(sanitizedPrefs);
    } catch (e) {
      console.error("Failed to parse preferences", e);
    }
  }
}

// Safe merge function that protects against prototype pollution
function safeObjectMerge(target, source) {
  const output = { ...target };
  
  if (source && typeof source === 'object') {
    Object.keys(source).forEach(key => {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        return; // Skip dangerous properties
      }
      
      if (source[key] && typeof source[key] === 'object') {
        output[key] = safeObjectMerge(output[key] || {}, source[key]);
      } else {
        output[key] = source[key];
      }
    });
  }
  
  return output;
}
```

### Libraries to Fix:
- lodash/fp (functional programming version with fewer vulnerabilities)
- json-stringify-safe
- serialize-javascript

## 9. Insufficient Logging & Monitoring
### Penetration Testing Steps
**Step 1:** Test for Error Logging: Trigger various errors and check if they're properly logged.
**Step 2:** Check User Activity Tracking: Verify if security-relevant user actions are logged.

### Example of a Flaw:
```jsx
// No logging of authentication attempts
function LoginForm() {
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.login(username, password);
      navigate("/dashboard");
    } catch (error) {
      setError("Login failed");
      // No logging of failed login attempts
    }
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
}

// No logging of important actions
function DeleteUserButton({ userId }) {
  const handleDelete = async () => {
    if (window.confirm("Are you sure?")) {
      await api.deleteUser(userId);
      // No logging of user deletion
    }
  };
  
  return <button onClick={handleDelete}>Delete User</button>;
}
```

### Remediation:
**Implement Client-Side Logging:**
```jsx
// Create a logging service
const logService = {
  logError: (error, context) => {
    console.error(error);
    // Send to backend logging service
    return fetch("/api/logs/error", {
      method: "POST",
      body: JSON.stringify({
        error: error.toString(),
        context,
        timestamp: new Date().toISOString(),
        url: window.location.href,
      }),
    });
  },
  
  logAction: (action, details) => {
    // Send to backend logging service
    return fetch("/api/logs/action", {
      method: "POST",
      body: JSON.stringify({
        action,
        details,
        timestamp: new Date().toISOString(),
        url: window.location.href,
      }),
    });
  },
};

// LoginForm with logging
function LoginForm() {
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.login(username, password);
      logService.logAction("login_success", { username });
      navigate("/dashboard");
    } catch (error) {
      setError("Login failed");
      logService.logError(error, {
        action: "login_attempt",
        username,
      });
    }
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
}

// DeleteUserButton with logging
function DeleteUserButton({ userId }) {
  const handleDelete = async () => {
    if (window.confirm("Are you sure?")) {
      try {
        await api.deleteUser(userId);
        logService.logAction("user_deleted", { userId });
      } catch (error) {
        logService.logError(error, {
          action: "delete_user_attempt",
          userId,
        });
      }
    }
  };
  
  return <button onClick={handleDelete}>Delete User</button>;
}
```

### Libraries to Fix:
- sentry-react
- react-error-boundary
- redux-logger (for Redux state changes)

## 10. Server-Side Request Forgery (SSRF)
### Penetration Testing Steps
**Step 1:** Identify URL Inputs: Look for features where the app fetches resources from user-provided URLs.
**Step 2:** Test with Internal URLs: Try accessing internal resources like `http://localhost` or `http://169.254.169.254/` (AWS metadata).

### Example of a Flaw:
```jsx
// Frontend component that makes a server-side request with user input
function ImageFetcher() {
  const [imageUrl, setImageUrl] = useState("");
  const [image, setImage] = useState(null);

  const fetchImage = async () => {
    // This might call a backend API that makes the request
    const response = await fetch(`/api/fetch-image?url=${imageUrl}`);
    const data = await response.json();
    setImage(data.imageData);
  };

  return (
    <div>
      <input
        type="text"
        value={imageUrl}
        onChange={(e) => setImageUrl(e.target.value)}
        placeholder="Enter image URL"
      />
      <button onClick={fetchImage}>Fetch Image</button>
      {image && <img src={`data:image/jpeg;base64,${image}`} alt="Fetched" />}
    </div>
  );
}
```

### Remediation:
**Validate URLs and Use Allowlists:**
```jsx
function ImageFetcher() {
  const [imageUrl, setImageUrl] = useState("");
  const [image, setImage] = useState(null);
  const [error, setError] = useState(null);

  // Validate URL is from an allowed domain
  const isAllowedDomain = (url) => {
    try {
      const urlObj = new URL(url);
      const allowedDomains = ["example.com", "trusted-images.com"];
      return allowedDomains.includes(urlObj.hostname);
    } catch (e) {
      return false;
    }
  };

  const fetchImage = async () => {
    setError(null);
    
    if (!imageUrl) {
      setError("Please enter a URL");
      return;
    }
    
    if (!isAllowedDomain(imageUrl)) {
      setError("URL domain not allowed");
      return;
    }
    
    try {
      const response = await fetch(`/api/fetch-image`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: imageUrl }),
      });
      
      if (!response.ok) {
        throw new Error("Failed to fetch image");
      }
      
      const data = await response.json();
      setImage(data.imageData);
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <div>
      <input
        type="text"
        value={imageUrl}
        onChange={(e) => setImageUrl(e.target.value)}
        placeholder="Enter image URL"
      />
      <button onClick={fetchImage}>Fetch Image</button>
      {error && <div className="error">{error}</div>}
      {image && <img src={`data:image/jpeg;base64,${image}`} alt="Fetched" />}
    </div>
  );
}
```

### Libraries to Fix:
- validator (for URL validation)
- url-parse (for URL parsing and validation)


##
##
