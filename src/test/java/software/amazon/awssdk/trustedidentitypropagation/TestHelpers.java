package software.amazon.awssdk.trustedidentitypropagation;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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

            System.out.println(map);
            return map;

        } catch (Exception e) {
            throw new RuntimeException("Failed to process integration test environment", e);
        }
    }

    public static RSAKey generateCustomJWK() {
        try {
            return new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString()) // Key ID
                .keyUse(KeyUse.SIGNATURE) // Key usage
                .algorithm(new Algorithm("RS256")) // Intended algorithm
                .generate();

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWK", e);
        }
    }

    public static RSAKey generateInvalidJWK() {
        try {
            // Generate a valid JWK first
            RSAKey validJwk = generateCustomJWK();

            // Create an invalid key by modifying some parameters
            return new RSAKey.Builder(validJwk.toPublicJWK())
                .privateExponent(validJwk.getPrivateExponent()) // Keep private exponent
                .keyID("invalid-key") // Change key ID
                .build();

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate invalid JWK", e);
        }
    }

    public static RSAKey getIntegrationTestPrivateKey() {


        try {
            String privateKey = System.getenv("INTEGRATION_TEST_PRIVATE_KEY");
            if (privateKey == null || privateKey.trim().isEmpty()) {
                throw new IllegalStateException(
                    "INTEGRATION_TEST_PRIVATE_KEY environment variable is not set");
            }
            return RSAKey.parse(privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process integration test environment", e);
        }
    }

    public static String generateWebToken(RSAKey jwk, Map<String, String> envMap)
        throws JOSEException {

        String idcUserName = envMap.get("IdcUserName");
        String idpIssuerUrl = envMap.get("IdpIssuerUrl");
        String idpAudience = envMap.get("IdpAudience");
        String idpSubject = envMap.get("IdpSubject");

        // Current time for token validity
        Date now = new Date();
        // Expiration time: current time + 1 hour
        Date expiryDate = new Date(now.getTime() + 3600000); // 1 hour in milliseconds

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .keyID(jwk.getKeyID())
            .build();

        final JWTClaimsSet payload = new JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .subject(idpSubject)
            .issuer(idpIssuerUrl)
            .audience(idpAudience)
            .issueTime(now)
            .expirationTime(expiryDate)
            .claim("userName", idcUserName)
            .build();

        final SignedJWT signedJWT = new SignedJWT(header, payload);
        final JWSSigner jwsSigner = getJWSSigner(jwk);
        signedJWT.sign(jwsSigner);

        return signedJWT.serialize();

    }

    private static JWSSigner getJWSSigner(RSAKey rsaKey) {
        try {
            return new RSASSASigner(rsaKey);
        } catch (JOSEException e) {
            throw new AssertionError(
                String.format("Failed to create JWSSigner from key %s", rsaKey.getKeyID()), e);
        }
    }


}
