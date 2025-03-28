package software.amazon.awssdk.trustedidentitypropagation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


public class TestHelpers {

    public static void main(String[] args) {
        // Make sure the main method is properly defined with correct signature
        Map<String, String> envMap = getIntegrationTestEnvironment();
        System.out.println("Integration Test Environment Variables:" + envMap.get("IdcUserId"));
    }


    public static Map<String, String> getIntegrationTestEnvironment() {
        try {
            String testVariables = System.getenv("INTEGRATION_TEST_VARIABLES");
            if (testVariables == null || testVariables.trim().isEmpty()) {
                throw new IllegalStateException(
                    "INTEGRATION_TEST_VARIABLES environment variable is not set");
            }
            Map<String, String> map = new HashMap();

            JsonElement jsonElement = JsonParser.parseString(testVariables);
            if (jsonElement == null || !jsonElement.isJsonObject()) {
                throw new IllegalStateException(
                    "Invalid JSON format in INTEGRATION_TEST_VARIABLES");
            }
            JsonObject obj = jsonElement.getAsJsonObject();

            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                map.put(entry.getKey(), entry.getValue().getAsString());
            }

            return map;

        } catch (Exception e) {
            throw new RuntimeException("Failed to process integration test environment", e);
        }
    }

    public static String generateInvalidWebToken() throws Exception {
        return Jwts.builder()
            .setHeaderParam("kid", "test")
            // Set standard claims
            .setId(UUID.randomUUID().toString())  // jwtid
            .setIssuer("idpIssuerUrl")
            .compact();
    }

    public static String generateWebToken(Map<String, String> envMap)
        throws Exception {

        String idcUserName = envMap.get("IdcUserName");
        String idpIssuerUrl = envMap.get("IdpIssuerUrl");
        String idpAudience = envMap.get("IdpAudience");
        String idpSubject = envMap.get("IdpSubject");

        // Current time for token validity
        Date now = new Date();
        // Expiration time: current time + 1 hour
        Date expiryDate = new Date(now.getTime() + 3600000); // 1 hour in milliseconds

        String privateKey = System.getenv("INTEGRATION_TEST_PRIVATE_KEY");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jwk = mapper.readTree(privateKey);
        String kid = jwk.get("kid").asText();

        Map<String, Object> claims = new HashMap<>();
        claims.put("userName", idcUserName);

        // Build the JWT
        String token = Jwts.builder()
            // Set custom claims
            .setClaims(claims)
            // Set header parameters
            .setHeaderParam("kid", kid)
            // Set standard claims
            .setId(UUID.randomUUID().toString())  // jwtid
            .setIssuer(idpIssuerUrl)
            .setAudience(idpAudience)
            .setSubject(idpSubject)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            // Sign the token
            .signWith(convertJwkToKey(privateKey), SignatureAlgorithm.RS256)
            .compact();
        return token;

    }


    public static Key convertJwkToKey(String jwkJson) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jwk = mapper.readTree(jwkJson);

        return convertRsaJwkToKey(jwk);
    }

    private static Key convertRsaJwkToKey(JsonNode jwk) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Check if it's a private or public key
        if (jwk.has("d")) {
            // Private key
            BigInteger modulus = new BigInteger(1,
                Base64.getUrlDecoder().decode(jwk.get("n").asText()));
            BigInteger privateExponent = new BigInteger(1,
                Base64.getUrlDecoder().decode(jwk.get("d").asText()));
            BigInteger publicExponent = new BigInteger(1,
                Base64.getUrlDecoder().decode(jwk.get("e").asText()));

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            return keyFactory.generatePrivate(keySpec);
        } else {
            // Public key
            BigInteger modulus = new BigInteger(1,
                Base64.getUrlDecoder().decode(jwk.get("n").asText()));
            BigInteger publicExponent = new BigInteger(1,
                Base64.getUrlDecoder().decode(jwk.get("e").asText()));

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            return keyFactory.generatePublic(keySpec);
        }
    }

}
