package software.amazon.awssdk.trustedidentitypropagation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;

import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.identity.spi.ResolveIdentityRequest;
import software.amazon.awssdk.services.s3.S3ServiceClientConfiguration;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.model.CreateTokenWithIamRequest;
import software.amazon.awssdk.services.ssooidc.model.CreateTokenWithIamResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

public class TrustedIdentityPropagationPluginTest {
    private IdentityProvider<AwsCredentialsIdentity> delegateCredentialsProvider = Mockito.mock(IdentityProvider.class);
    private String idToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZ"
        + "SI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private String idcIdToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZ"
        + "SI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzdHM6aWRlbnRpdHlfY29udGV4dCI6ImlkY29udGV4dCJ9.5vKibdvG2tmtmRtmgUaXcbSIkLwP67h6oIyVMBwPt1Q";
    private String roleArn = "arn:aws:iam::123456789101:role/example";
    private String ssoClientId = "arn:aws:sso::123456789101:application/ssoins-1234567891234567/apl-1234567891234567";
    private StsClient stsClient = Mockito.mock(StsClient.class);
    private SsoOidcClient oidcClient = Mockito.mock(SsoOidcClient.class);
    private TrustedIdentityPropagationPlugin trustedIdentityPropagationPlugin = TrustedIdentityPropagationPlugin.builder()
        .idTokenSupplier(() -> idToken)
        .applicationArn(ssoClientId)
        .accessRoleArn(roleArn)
        .stsClient(stsClient)
        .ssoOidcClient(oidcClient)
        .build();
    private AwsCredentialsIdentity staticCredentials =
        AwsCredentialsIdentity.builder()
            .accessKeyId("akid")
            .secretAccessKey("skid")
            .accountId("123")
            .build();
    private Credentials stsCreds = Credentials.builder()
        .accessKeyId("akid")
        .secretAccessKey("skid")
        .sessionToken("st")
        .build();

    @BeforeEach
    public void setup() {
        Mockito.when(delegateCredentialsProvider.resolveIdentity(any(ResolveIdentityRequest.class)))
            .thenAnswer(i -> CompletableFuture.completedFuture(staticCredentials));
        Mockito.when(stsClient.assumeRole(any(AssumeRoleRequest.class))).thenReturn(
            AssumeRoleResponse.builder().credentials(stsCreds).build());
        Mockito.when(oidcClient.createTokenWithIAM(any(CreateTokenWithIamRequest.class))).thenReturn(
            CreateTokenWithIamResponse.builder().idToken(idcIdToken).build());
    }
    @AfterEach
    public void teardown() {
      Mockito.reset(oidcClient, stsClient, delegateCredentialsProvider);
    }

    @Test
    public void tipPlugin_modifiesCredentialsProvider() {
        S3ServiceClientConfiguration.Builder clientConfiguration =
            S3ServiceClientConfiguration.builder()
                .credentialsProvider(delegateCredentialsProvider);

        trustedIdentityPropagationPlugin.configureClient(clientConfiguration);

        assertThat(clientConfiguration.credentialsProvider()).isNotEqualTo(delegateCredentialsProvider);
    }

    @Test
    public void tipPlugin_throwsExceptionForMissingArguments() {
        assertThatThrownBy(() -> TrustedIdentityPropagationPlugin.builder()
            .applicationArn(ssoClientId)
            .accessRoleArn(roleArn)
            .build()).isInstanceOfAny(RuntimeException.class);

        assertThatThrownBy(() -> TrustedIdentityPropagationPlugin.builder()
            .idTokenSupplier(() -> idToken)
            .accessRoleArn(roleArn)
            .build()).isInstanceOfAny(RuntimeException.class);

        assertThatThrownBy(() -> TrustedIdentityPropagationPlugin.builder()
            .idTokenSupplier(() -> idToken)
            .applicationArn(ssoClientId)
            .build()).isInstanceOfAny(RuntimeException.class);
    }
}
