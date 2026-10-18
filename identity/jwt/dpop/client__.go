package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---- base64url helpers (no padding) ----
var b64u = base64.RawURLEncoding

func b64uEncode(b []byte) string {
	return b64u.EncodeToString(b)
}

func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ---- JWK + thumbprint (RFC 7638) ----

type jwkEC struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwkThumbprintRFC7638 returns base64url(SHA-256(canonicalJSON)) where canonical JSON is
// {"crv":"P-256","kty":"EC","x":"...","y":"..."} with keys in lexicographic order.
// (We construct it manually to guarantee canonical ordering.)
func jwkThumbprintRFC7638(j jwkEC) string {
	// Keys must be ordered: crv, kty, x, y
	canon := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j.Crv, j.Kty, j.X, j.Y)
	return b64uEncode(sha256Bytes([]byte(canon)))
}

// ---- JWT building (HS256 + ES256) ----

// jsonCompactSorted is used for JWT header/payload encoding.
// For JWT itself, strict “sorted keys” isn’t required by the spec, but your server might be
// parsing/validating. To be safe and deterministic, we encode structs (stable order) rather than maps.
func jsonCompact(v any) ([]byte, error) {
	return json.Marshal(v)
}

func jwtHS256(header any, payload any, secret []byte) (string, error) {
	hb, err := jsonCompact(header)
	if err != nil {
		return "", err
	}
	pb, err := jsonCompact(payload)
	if err != nil {
		return "", err
	}
	h := b64uEncode(hb)
	p := b64uEncode(pb)

	signingInput := []byte(h + "." + p)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingInput)
	sig := mac.Sum(nil)

	return h + "." + p + "." + b64uEncode(sig), nil
}

func leftPad32(b []byte) []byte {
	if len(b) > 32 {
		// Should not happen for P-256 r/s
		return b[len(b)-32:]
	}
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// jwtES256 signs "header.payload" using ECDSA P-256 and returns compact JWS with raw signature r||s (64 bytes).
func jwtES256(priv *ecdsa.PrivateKey, header any, payload any) (string, error) {
	hb, err := jsonCompact(header)
	if err != nil {
		return "", err
	}
	pb, err := jsonCompact(payload)
	if err != nil {
		return "", err
	}
	h := b64uEncode(hb)
	p := b64uEncode(pb)

	signingInput := []byte(h + "." + p)
	digest := sha256Bytes(signingInput)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return "", err
	}

	rb := leftPad32(r.Bytes())
	sb := leftPad32(s.Bytes())
	rawSig := append(rb, sb...)

	return h + "." + p + "." + b64uEncode(rawSig), nil
}

// ---- Key generation + JWK extraction ----

func genP256KeyAndJWK() (*ecdsa.PrivateKey, jwkEC, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, jwkEC{}, err
	}

	// Public key coordinates (big.Int) -> fixed 32-byte big-endian
	x := leftPad32(priv.PublicKey.X.Bytes())
	y := leftPad32(priv.PublicKey.Y.Bytes())

	jwk := jwkEC{
		Kty: "EC",
		Crv: "P-256",
		X:   b64uEncode(x),
		Y:   b64uEncode(y),
	}
	return priv, jwk, nil
}

// ---- Claims ----

type accessHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type accessPayload struct {
	Sub   string `json:"sub"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Scope string `json:"scope"`
	Cnf   struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Jwk jwkEC  `json:"jwk"`
}

type dpopPayload struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Ath string `json:"ath"`
}

// ---- Simple UUIDv4 (no deps) ----

func uuidv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Set version (4) and variant (10)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	hex := func(x byte) string { return fmt.Sprintf("%02x", x) }
	return strings.Join([]string{
		hex(b[0]), hex(b[1]), hex(b[2]), hex(b[3]), "-",
		hex(b[4]), hex(b[5]), "-",
		hex(b[6]), hex(b[7]), "-",
		hex(b[8]), hex(b[9]), "-",
		hex(b[10]), hex(b[11]), hex(b[12]), hex(b[13]), hex(b[14]), hex(b[15]),
	}, ""), nil
}

// ---- HTTP ----

func call(ctx context.Context, url, method, authScheme, accessToken, proof string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", authScheme+" "+accessToken)
	req.Header.Set("DPoP", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(bodyBytes), nil
}

// ---- main ----

func main() {
	var (
		url        = flag.String("url", getenv("DPOP_URL", "http://127.0.0.1:8080/api/hello"), "Resource URL")
		method     = flag.String("method", getenv("DPOP_METHOD", "GET"), "HTTP method")
		secretStr  = flag.String("secret", getenv("DPOP_SECRET", "super-secret-demo-key-change-me-please-123456"), "HS256 HMAC secret (must match server)")
		authScheme = flag.String("auth-scheme", getenv("DPOP_SCHEME", "DPoP"), "Authorization scheme: DPoP or Bearer")
		expSecs    = flag.Int64("exp-seconds", 300, "Access token lifetime seconds")
		noReplay   = flag.Bool("no-replay", false, "Do not send replay request")
		verbose    = flag.Bool("verbose", false, "Print claims and JWK")
	)
	flag.Parse()

	// 1) Keypair + JWK + jkt
	priv, jwk, err := genP256KeyAndJWK()
	if err != nil {
		die(err)
	}
	jkt := jwkThumbprintRFC7638(jwk)

	// 2) Mint HS256 access token with cnf.jkt
	now := time.Now().Unix()
	ah := accessHeader{Alg: "HS256", Typ: "JWT"}

	var ap accessPayload
	ap.Sub = "htb-user"
	ap.Iat = now
	ap.Exp = now + *expSecs
	ap.Scope = "demo"
	ap.Cnf.Jkt = jkt

	accessToken, err := jwtHS256(ah, ap, []byte(*secretStr))
	if err != nil {
		die(err)
	}

	// 3) Mint DPoP proof (ES256) with ath
	ath := b64uEncode(sha256Bytes([]byte(accessToken)))

	jti, err := uuidv4()
	if err != nil {
		die(err)
	}

	dh := dpopHeader{Typ: "dpop+jwt", Alg: "ES256", Jwk: jwk}
	dp := dpopPayload{
		Htm: strings.ToUpper(*method),
		Htu: *url,
		Iat: now,
		Jti: jti,
		Ath: ath,
	}

	proof, err := jwtES256(priv, dh, dp)
	if err != nil {
		die(err)
	}

	if *verbose {
		fmt.Println("\n--- JWK ---")
		jb, _ := json.MarshalIndent(jwk, "", "  ")
		fmt.Println(string(jb))

		fmt.Println("\n--- Access Token Claims ---")
		ab, _ := json.MarshalIndent(ap, "", "  ")
		fmt.Println(string(ab))

		fmt.Println("\n--- DPoP Proof Claims ---")
		db, _ := json.MarshalIndent(dp, "", "  ")
		fmt.Println(string(db))
	}

	// 4) Call #1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status1, body1, err := call(ctx, *url, strings.ToUpper(*method), *authScheme, accessToken, proof)
	if err != nil {
		die(err)
	}
	fmt.Printf("\n[FIRST CALL] HTTP %d\n", status1)
	if strings.TrimSpace(body1) != "" {
		fmt.Println(body1)
	}

	if *noReplay {
		return
	}

	// 5) Call #2 (replay exact same proof -> should fail if RS caches jti)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	status2, body2, err := call(ctx2, *url, strings.ToUpper(*method), *authScheme, accessToken, proof)
	if err != nil {
		die(err)
	}
	fmt.Printf("\n[REPLAY (same proof)] HTTP %d\n", status2)
	if strings.TrimSpace(body2) != "" {
		fmt.Println(body2)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// (unused but handy) bigIntToFixed ensures exact byte length (not needed beyond leftPad32)
func bigIntToFixed(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
