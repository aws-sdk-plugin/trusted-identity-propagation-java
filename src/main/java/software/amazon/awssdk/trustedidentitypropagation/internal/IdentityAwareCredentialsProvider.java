/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package software.amazon.awssdk.trustedidentitypropagation.internal;

import static software.amazon.awssdk.trustedidentitypropagation.Constants.CONTEXT_PROVIDER_IDENTITY_CENTER;
import static software.amazon.awssdk.trustedidentitypropagation.Constants.JWT_BEARER_GRANT_URI;
import static software.amazon.awssdk.trustedidentitypropagation.Helpers.getIdentityEnhancedSessionName;

import com.nimbusds.jose.JWSObject;
import java.text.ParseException;
import java.util.Map;
import java.util.function.Supplier;
import software.amazon.awssdk.annotations.SdkInternalApi;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.model.CreateTokenWithIamRequest;
import software.amazon.awssdk.services.ssooidc.model.CreateTokenWithIamResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.ProvidedContext;
import software.amazon.awssdk.utils.Logger;

@SdkInternalApi
public class IdentityAwareCredentialsProvider implements AwsCredentialsProvider {

    private static final Logger LOGGER = Logger.loggerFor(IdentityAwareCredentialsProvider.class);

    private static final long FIFTEEN_MINUTES_IN_MS = 15L * 60L * 1000L;
    private static final int FIFTEEN_MINUTES_IN_SEC = 15 * 60;
    private AwsCredentials identityAwareCredentials;

    private String applicationArn;
    private String accessRoleArn;
    private Supplier<String> webTokenProvider;

    private StsClient stsClient;
    private SsoOidcClient ssoOidcClient;


    public IdentityAwareCredentialsProvider(StsClient stsClient,
        SsoOidcClient ssoOidcClient,
        Supplier<String> webTokenProvider, String applicationArn, String accessRoleArn) {
        this.stsClient = stsClient;
        this.ssoOidcClient = ssoOidcClient;
        this.webTokenProvider = webTokenProvider;
        this.applicationArn = applicationArn;
        this.accessRoleArn = accessRoleArn;
    }

    @Override
    public AwsCredentials resolveCredentials() {
        if (identityAwareCredentials == null) {
            try {
                identityAwareCredentials = generateIdentityAwareCreds();
            } catch (ParseException e) {
                LOGGER.error(() -> "Failed to generate identity aware credentials", e.getCause());
                throw new RuntimeException(e);
            }
        }
        return identityAwareCredentials;
    }


    private AwsSessionCredentials generateIdentityAwareCreds() throws ParseException {

        CreateTokenWithIamResponse createTokenWithIamResponse = ssoOidcClient.createTokenWithIAM(
            CreateTokenWithIamRequest.builder()
                .grantType(JWT_BEARER_GRANT_URI)
                .assertion(webTokenProvider.get())
                .clientId(applicationArn)
                .build());
        ;

        String idTokenFromTti = createTokenWithIamResponse.idToken();
        JWSObject idTokenJws = JWSObject.parse(idTokenFromTti);

        // TODO: To be removed. We are going to get `sts:identity_context` from the response of `CreateTokenWithIAM`.
        Map<String, Object> idTokenObject = idTokenJws.getPayload().toJSONObject();

        String contextAssertion = (String) idTokenObject.get("sts:identity_context");
        String sub = (String) idTokenObject.get("sub");
        AssumeRoleResponse assumeRoleResponse = stsClient.assumeRole(AssumeRoleRequest.builder()
            .roleArn(accessRoleArn)
            .durationSeconds(FIFTEEN_MINUTES_IN_SEC)
            .roleSessionName(getIdentityEnhancedSessionName(applicationArn))
            .overrideConfiguration(
                c -> c.credentialsProvider(ssoOidcClient.serviceClientConfiguration()
                    .credentialsProvider()))
            .providedContexts(ProvidedContext.builder()
                .providerArn(CONTEXT_PROVIDER_IDENTITY_CENTER)
                .contextAssertion(contextAssertion)
                .build())
            .build());

        AwsSessionCredentials credentials = new AwsSessionCredentials.Builder()
            .accessKeyId(assumeRoleResponse.credentials().accessKeyId())
            .secretAccessKey(assumeRoleResponse.credentials().secretAccessKey())
            .sessionToken(assumeRoleResponse.credentials().sessionToken())
            .build();

        return credentials;
    }

}
