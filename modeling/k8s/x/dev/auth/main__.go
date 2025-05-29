package main

import (
  "context"
  "crypto/rsa"
  "crypto/x509"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "io/ioutil"
  "log"
  "net/http"
  "time"

  "github.com/go-redis/redis/v8"
  "github.com/golang-jwt/jwt/v4"
  "go.mongodb.org/mongo-driver/bson"
  "go.mongodb.org/mongo-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
  "golang.org/x/crypto/bcrypt"
  "github.com/google/uuid"
)

type TierConfig struct {
  MaxChallenges int    `bson:"maxChallenges" json:"maxChallenges"`
  MaxCPU        string `bson:"maxCPU" json:"maxCPU"`
  MaxMemory     string `bson:"maxMemory" json:"maxMemory"`
}

type User struct {
  ID            string                `bson:"_id" json:"id"`
  Email         string                `bson:"email" json:"email"`
  PasswordHash  string                `bson:"passwordHash"`
  Subscriptions []string              `bson:"subscriptions" json:"subscriptions"`
  TierLimits    map[string]TierConfig `bson:"tierLimits" json:"tierLimits"`
}

// JWTClaims extends RegisteredClaims with our custom fields
type JWTClaims struct {
  UserID        string                `json:"user_id"`
  Email         string                `json:"email"`
  Subscriptions []string              `json:"subscriptions"`
  TierLimits    map[string]TierConfig `json:"tier_limits"`
  SessionID     string                `json:"session_id"`
  jwt.RegisteredClaims
}

type AuthServer struct {
  mongoColl *mongo.Collection
  redis     *redis.Client
  privKey   *rsa.PrivateKey
  pubKey    *rsa.PublicKey
  ctx       context.Context
}

func main() {
  // Load keys
  priv := mustLoadPrivateKey("/etc/project-x/keys/private.key")
  pub := mustLoadPublicKey("/etc/project-x/keys/public.key")

  // MongoDB setup
  ctx := context.Background()
  client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://user:pass@cluster0.mongodb.net"))
  if err != nil {
    log.Fatal(err)
  }
  users := client.Database("projectx").Collection("users")

  // Redis setup
  rdb := redis.NewClient(&redis.Options{
    Addr: "redis.project-x-infra.svc.cluster.local:6379",
  })

  auth := &AuthServer{
    mongoColl: users,
    redis:     rdb,
    privKey:   priv,
    pubKey:    pub,
    ctx:       ctx,
  }

  http.HandleFunc("/auth/login", auth.loginHandler)
  http.HandleFunc("/auth/validate", auth.validateHandler)
  log.Println("Auth Service listening :8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}

// loginHandler verifies credentials, creates a session & JWT
func (a *AuthServer) loginHandler(w http.ResponseWriter, r *http.Request) {
  var req struct{ Email, Password string }
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, "invalid request", http.StatusBadRequest)
    return
  }

  // Fetch user
  var user User
  if err := a.mongoColl.FindOne(a.ctx, bson.M{"email": req.Email}).Decode(&user); err != nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
  }

  // Check password
  if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
  }

  // Create session ID
  sessionID := uuid.NewString()
  sessionKey := "session:" + sessionID

  // Store session in Redis
  sessData := map[string]interface{}{
    "user_id":       user.ID,
    "email":         user.Email,
    "subscriptions": user.Subscriptions,
    "tier_limits":   user.TierLimits,
  }
  a.redis.HSet(a.ctx, sessionKey, sessData)
  a.redis.Expire(a.ctx, sessionKey, 24*time.Hour)

  // Generate JWT
  now := time.Now()
  claims := JWTClaims{
    UserID:        user.ID,
    Email:         user.Email,
    Subscriptions: user.Subscriptions,
    TierLimits:    user.TierLimits,
    SessionID:     sessionID,
    RegisteredClaims: jwt.RegisteredClaims{
      ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
      IssuedAt:  jwt.NewNumericDate(now),
      NotBefore: jwt.NewNumericDate(now),
      Issuer:    "project-x.auth",
      Subject:   user.ID,
      Audience:  []string{"project-x"},
    },
  }
  token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
  signed, err := token.SignedString(a.privKey)
  if err != nil {
    http.Error(w, "token error", http.StatusInternalServerError)
    return
  }

  // Return token JSON (can also set as HttpOnly cookie)
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(map[string]interface{}{
    "token":     signed,
    "expiresAt": claims.ExpiresAt,
  })
}

// validateHandler checks a JWT and echo claims
func (a *AuthServer) validateHandler(w http.ResponseWriter, r *http.Request) {
  auth := r.Header.Get("Authorization")
  if !strings.HasPrefix(auth, "Bearer ") {
    http.Error(w, "missing token", http.StatusUnauthorized)
    return
  }
  tok := strings.TrimPrefix(auth, "Bearer ")
  token, err := jwt.ParseWithClaims(tok, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
    if t.Method != jwt.SigningMethodRS256 {
      return nil, fmt.Errorf("unexpected alg")
    }
    return a.pubKey, nil
  })
  if err != nil || !token.Valid {
    http.Error(w, "invalid token", http.StatusUnauthorized)
    return
  }
  claims := token.Claims.(*JWTClaims)
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(claims)
}

// Utility: load private key from PEM
func mustLoadPrivateKey(path string) *rsa.PrivateKey {
  b, err := ioutil.ReadFile(path); if err != nil { log.Panic(err) }
  block, _ := pem.Decode(b); if block == nil { log.Panic("invalid key PEM") }
  key, err := x509.ParsePKCS1PrivateKey(block.Bytes); if err != nil { log.Panic(err) }
  return key
}

// Utility: load public key from PEM
func mustLoadPublicKey(path string) *rsa.PublicKey {
  b, err := ioutil.ReadFile(path); if err != nil { log.Panic(err) }
  block, _ := pem.Decode(b); if block == nil { log.Panic("invalid key PEM") }
  iface, err := x509.ParsePKIXPublicKey(block.Bytes); if err != nil { log.Panic(err) }
  pub, ok := iface.(*rsa.PublicKey); if !ok { log.Panic("not RSA pubkey") }
  return pub
}
//
//
