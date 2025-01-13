import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtForge {

    public static void main(String[] args) throws Exception {
        // Example payload
        Map<String, Object> payload = new HashMap<>();
        payload.put("hello", "world");

        // 1. HMAC Signing and Verification
        System.out.println("=== HMAC Signing and Verification ===");
        Key hmacKey = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generate a random HMAC key

        String hmacToken = Jwts.builder()
                .setClaims(payload)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiration
                .signWith(hmacKey)
                .compact();

        System.out.println("HMAC Token: " + hmacToken);
        System.out.println("HMAC Key (Base64): " + Base64.getEncoder().encodeToString(hmacKey.getEncoded()));

        // Verify the HMAC token
        Map<String, Object> hmacDecodedPayload = Jwts.parserBuilder()
                .setSigningKey(hmacKey)
                .build()
                .parseClaimsJws(hmacToken)
                .getBody();

        System.out.println("Decoded HMAC Payload: " + hmacDecodedPayload);

        // 2. RSA Signing and Verification
        System.out.println("\n=== RSA Signing and Verification ===");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

        String rsaToken = Jwts.builder()
                .setClaims(payload)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiration
                .signWith(rsaKeyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

        System.out.println("RSA Token: " + rsaToken);
        System.out.println("RSA Public Key: " + Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
        System.out.println("RSA Private Key: " + Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));

        // Verify the RSA token
        Map<String, Object> rsaDecodedPayload = Jwts.parserBuilder()
                .setSigningKey(rsaKeyPair.getPublic())
                .build()
                .parseClaimsJws(rsaToken)
                .getBody();

        System.out.println("Decoded RSA Payload: " + rsaDecodedPayload);
    }
}
