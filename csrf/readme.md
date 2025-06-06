

# CSRF vs XSS: Enhanced Technical Guide with Visual Diagrams

## Attack Flow Diagrams

### CSRF Attack Flow
```
┌─────────────┐    1. Visit malicious site    ┌─────────────┐
│   Victim    │ ──────────────────────────────▶│  Attacker   │
│   Browser   │                                │    Site     │
└─────────────┘                                └─────────────┘
       │                                              │
       │ 2. Malicious site serves                     │
       │    forged request                            │
       ▼                                              │
┌─────────────┐                                       │
│   Victim    │                                       │
│   Browser   │                                       │
│ ┌─────────┐ │ 3. Browser auto-includes               │
│ │ Cookies │ │    auth cookies                       │
│ │ Session │ │                                       │
│ └─────────┘ │                                       │
└─────────────┘                                       │
       │                                              │
       │ 4. Authenticated request                     │
       │    (victim unaware)                          │
       ▼                                              │
┌─────────────┐                                       │
│   Target    │ 5. Executes action                    │
│   Website   │    (transfer money, etc.)             │
│             │                                       │
└─────────────┘                                       │
       │                                              │
       │ 6. Success response                          │
       └──────────────────────────────────────────────┘
```

### XSS Attack Flow
```
┌─────────────┐    1. Inject malicious script    ┌─────────────┐
│  Attacker   │ ─────────────────────────────────▶│   Target    │
│             │                                   │   Website   │
└─────────────┘                                   └─────────────┘
                                                         │
                                                         │ 2. Store/Reflect
                                                         │    malicious script
                                                         ▼
┌─────────────┐    3. Visit infected page        ┌─────────────┐
│   Victim    │ ──────────────────────────────────│   Target    │
│   Browser   │                                   │   Website   │
└─────────────┘                                   └─────────────┘
       ▲                                                 │
       │                                                 │ 4. Serve page with
       │                                                 │    malicious script
       │                                                 ▼
       │                                          ┌─────────────┐
       │ 6. Script executes in                    │   Victim    │
       │    target's context                      │   Browser   │
       │                                          │ ┌─────────┐ │
       │                                          │ │ Cookies │ │
       │                                          │ │ Session │ │
       │                                          │ └─────────┘ │
       │                                          └─────────────┘
       │                                                 │
       │                                                 │ 5. Malicious script
       │                                                 │    accesses data
       │                                                 ▼
       │                                          ┌─────────────┐
       └──────────────────────────────────────────│  Attacker   │
                 7. Steal data/credentials        │   Server    │
                                                  └─────────────┘
```

## Comprehensive Comparison Table

| Category | CSRF | XSS |
|----------|------|-----|
| **Attack Vector** | Forged cross-site requests | Malicious script injection |
| **Execution Context** | Victim's browser → Target site | Target site → Victim's browser |
| **Trust Exploitation** | Site trusts authenticated user | User trusts legitimate site |
| **User Awareness** | Often completely unaware | May notice unusual behavior |
| **Persistence** | Per-request basis | Can be persistent (Stored XSS) |
| **Authentication Required** | Yes (victim must be logged in) | No (but more powerful if authenticated) |
| **Same-Origin Limitation** | Bypasses (cross-site nature) | Executes within origin |
| **Primary Impact** | Unauthorized actions | Data theft, session hijacking |
| **Detection Difficulty** | Moderate (network analysis) | High (content analysis required) |

## Attack Scenarios Matrix

### CSRF Scenarios
```
┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│   Attack Type       │   Delivery Method   │   Target Action     │   Stealth Level     │
├─────────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Form Auto-Submit    │ Malicious Website   │ State Change        │ High                │
│ Image Tag Exploit   │ Email/Website       │ GET-based Action    │ Very High           │
│ AJAX Request        │ Malicious Website   │ API Calls           │ Medium              │
│ File Upload         │ Malicious Website   │ File System Access  │ Medium              │
│ WebSocket Hijack    │ Malicious Website   │ Real-time Actions   │ High                │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

### XSS Scenarios
```
┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│   XSS Type          │   Injection Point   │   Payload Delivery  │   Persistence       │
├─────────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Reflected           │ URL Parameters      │ Malicious Link      │ Temporary           │
│ Stored              │ Database            │ User Input Forms    │ Permanent           │
│ DOM-based           │ Client-side JS      │ URL Fragments       │ Temporary           │
│ Mutation-based      │ DOM Manipulation    │ Dynamic Content     │ Temporary           │
│ Server-side         │ Template Engine     │ Server Processing   │ Permanent           │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

## Technical Implementation Comparison

### CSRF Attack Implementations

#### Simple Form-Based CSRF
```ascii
Attacker Site Structure:
┌─────────────────────────────────────────┐
│ <html>                                  │
│   <body onload="document.forms[0].      │
│                 submit()">              │
│     <form action="https://bank.com/     │
│           transfer" method="POST">      │
│       <input name="to" value="evil">   │
│       <input name="amount" value="1000">│
│     </form>                             │
│   </body>                              │
│ </html>                                 │
└─────────────────────────────────────────┘
```

#### JSON API CSRF
```ascii
Modern API Attack:
┌─────────────────────────────────────────┐
│ fetch('https://api.target.com/users',   │
│   {                                     │
│     method: 'DELETE',                   │
│     credentials: 'include',             │
│     headers: {                          │
│       'Content-Type': 'application/json'│
│     },                                  │
│     body: JSON.stringify({id: 'victim'})│
│   }                                     │
│ );                                      │
└─────────────────────────────────────────┘
```

### XSS Attack Implementations

#### Reflected XSS Flow
```ascii
Request Flow:
┌─────────────┐    GET /search?q=<script>  ┌─────────────┐
│   Victim    │ ─────────alert('XSS')──────▶│   Target    │
│   Browser   │                             │   Server    │
└─────────────┘                             └─────────────┘
       ▲                                           │
       │                                           │
       │ HTTP/1.1 200 OK                          │
       │ <h1>Results for: <script>                │
       │ alert('XSS')</script></h1>               │
       └───────────────────────────────────────────┘
```

#### Stored XSS Database Flow
```ascii
Database Injection:
┌─────────────┐    POST /comment           ┌─────────────┐
│  Attacker   │ ──────────────────────────▶│   Web       │
│             │  payload: <script>evil()   │   Server    │
└─────────────┘                             └─────────────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │  Database   │
                                            │ ┌─────────┐ │
                                            │ │ comments│ │
                                            │ │ <script>│ │
                                            │ │ evil()  │ │
                                            │ └─────────┘ │
                                            └─────────────┘
                                                   │
┌─────────────┐    GET /comments           ┌─────────────┐
│   Victim    │ ◄──────────────────────────│   Web       │
│   Browser   │  <script>evil()</script>   │   Server    │
└─────────────┘                             └─────────────┘
```

## Defense Mechanisms Comparison

### CSRF Defense Architecture
```ascii
Defense Layers:
┌─────────────────────────────────────────────────────────────┐
│                    CSRF Defense Stack                       │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: SameSite Cookies                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Set-Cookie: session=abc123; SameSite=Strict; Secure    │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: CSRF Tokens                                        │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ <input type="hidden" name="csrf" value="random_token">  │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Origin/Referer Validation                          │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ if (origin !== 'https://trusted-site.com') reject()    │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Custom Headers                                     │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ X-Requested-With: XMLHttpRequest                        │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### XSS Defense Architecture
```ascii
Defense Layers:
┌─────────────────────────────────────────────────────────────┐
│                     XSS Defense Stack                       │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Input Validation & Sanitization                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Input → Validate → Sanitize → Encode → Store/Display   │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Content Security Policy (CSP)                      │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Content-Security-Policy: script-src 'self' 'nonce-xyz' │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Output Encoding                                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ <script> → &lt;script&gt;                               │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: HTTPOnly Cookies                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Set-Cookie: session=abc123; HttpOnly; Secure           │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Combined Attack Scenario

### XSS-Enhanced CSRF Attack Flow
```ascii
Advanced Combined Attack:
                    ┌─────────────┐
                    │  Attacker   │
                    │   Server    │
                    └─────────────┘
                           │
                           │ 1. Inject XSS payload
                           ▼
    ┌─────────────┐ ──────────────────── ┌─────────────┐
    │   Victim    │ 2. Visit target site │   Target    │
    │   Browser   │ ◄─────────────────── │   Website   │
    └─────────────┘                      └─────────────┘
           │                                     │
           │ 3. XSS payload executes            │
           ▼                                     │
    ┌─────────────┐                             │
    │   Malicious │ 4. Extract CSRF token       │
    │   Script    │ ◄───────────────────────────┘
    │   Execution │
    └─────────────┘
           │
           │ 5. Forge authenticated request
           │    with valid CSRF token
           ▼
    ┌─────────────┐
    │   Target    │ 6. Execute privileged action
    │   Website   │    (appears legitimate)
    │   API       │
    └─────────────┘
```

## 2025 Threat Landscape

### Emerging Attack Vectors
```ascii
Modern Web Attack Surface:
┌─────────────────────────────────────────────────────────────┐
│                    Browser Environment                       │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│ │   Main      │ │   Service   │ │   Web       │ │  WASM   │ │
│ │   Thread    │ │   Worker    │ │  Worker     │ │ Module  │ │
│ │   ┌─────┐   │ │   ┌─────┐   │ │   ┌─────┐   │ │ ┌─────┐ │ │
│ │   │ XSS │   │ │   │ XSS │   │ │   │ XSS │   │ │ │ XSS │ │ │
│ │   └─────┘   │ │   └─────┘   │ │   └─────┘   │ │ └─────┘ │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│ │   Browser   │ │   PWA       │ │   Extension │ │  iframe │ │
│ │   Extension │ │   Context   │ │   Content   │ │ Context │ │
│ │   ┌─────┐   │ │   ┌─────┐   │ │   ┌─────┐   │ │ ┌─────┐ │ │
│ │   │CSRF │   │ │   │CSRF │   │ │   │CSRF │   │ │ │CSRF │ │ │
│ │   └─────┘   │ │   └─────┘   │ │   └─────┘   │ │ └─────┘ │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────────┘
```

