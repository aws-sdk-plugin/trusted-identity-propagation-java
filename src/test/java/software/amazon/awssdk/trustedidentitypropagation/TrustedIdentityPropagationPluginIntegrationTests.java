package software.amazon.awssdk.trustedidentitypropagation;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.model.InvalidGrantException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

public class TrustedIdentityPropagationPluginIntegrationTests {

    @Test
    public void testInValidWebToken() throws Exception {

        Map<String, String> envMap = TestHelpers.getIntegrationTestEnvironment();
        RSAKey rsaKey = TestHelpers.generateInvalidJWK();
        String idToken = TestHelpers.generateWebToken(rsaKey, envMap);
        String idcApplicationArn = envMap.get("IdcApplicationArn");
        String AccessRoleArn = envMap.get("AccessRoleArn");

        System.out.println(idToken);
        StsClient client = StsClient.builder()
            .region(Region.US_EAST_1)
            .credentialsProvider(AnonymousCredentialsProvider.create()).build();

        TrustedIdentityPropagationPlugin trustedIdentityPropagationPlugin = TrustedIdentityPropagationPlugin.builder()
            .stsClient(client)
            .idTokenSupplier(() -> idToken)
            .applicationArn(idcApplicationArn)
            .accessRoleArn(AccessRoleArn)
            .ssoOidcClient(SsoOidcClient.builder().region(Region.US_EAST_1).build())
            .build();

        StsClient stsClient =
            StsClient.builder().region(Region.US_EAST_1).addPlugin(trustedIdentityPropagationPlugin)
                .build();

        Exception exception = assertThrows(InvalidGrantException.class, () -> stsClient.getCallerIdentity());
        assertTrue(exception.getMessage().contains("Service returned error code InvalidGrantException"));

    }



    @Test
    public void testValidWebToken() throws Exception {
        Map<String, String> envMap = TestHelpers.getIntegrationTestEnvironment();
        RSAKey rsaKey = TestHelpers.getIntegrationTestPrivateKey();
        String idToken = TestHelpers.generateWebToken(rsaKey, envMap);
        String idcApplicationArn = envMap.get("IdcApplicationArn");
        String AccessRoleArn = envMap.get("AccessRoleArn");

        StsClient client = StsClient.builder()
            .region(Region.US_EAST_1)
            .credentialsProvider(AnonymousCredentialsProvider.create()).build();

        TrustedIdentityPropagationPlugin trustedIdentityPropagationPlugin = TrustedIdentityPropagationPlugin.builder()
            .stsClient(client)
            .idTokenSupplier(() -> idToken)
            .applicationArn(idcApplicationArn)
            .accessRoleArn(AccessRoleArn)
            .ssoOidcClient(SsoOidcClient.builder().region(Region.US_EAST_1).build())
            .build();

        // tipStsClient will be used to get the caller identity through trustedIdentityPropagationPlugin to ensure propagation works
        // The JWT that we generate for the integration tests uses the fake IDP endpoint for testing as the issuer URL
        // then we sign that with this private key to generate token and will use it for contextAssertion
        StsClient tipStsClient =
            StsClient.builder().region(Region.US_EAST_1).addPlugin(trustedIdentityPropagationPlugin)
                .build();
        assertNotNull(tipStsClient);
        GetCallerIdentityResponse getCallerIdentityResponse = tipStsClient.getCallerIdentity();

        String sessionName = Helpers.getIdentityEnhancedSessionName(idcApplicationArn);
        assertNotNull(getCallerIdentityResponse);
        assertTrue(getCallerIdentityResponse.arn().contains(sessionName));
        assertTrue(getCallerIdentityResponse.userId().contains(sessionName));
    }
}
