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

package software.amazon.awssdk.trustedidentitypropagation;

import static software.amazon.awssdk.trustedidentitypropagation.Helpers.getBootstrapSessionName;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import software.amazon.awssdk.annotations.Immutable;
import software.amazon.awssdk.annotations.Mutable;
import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.awscore.AwsServiceClientConfiguration;
import software.amazon.awssdk.core.SdkPlugin;
import software.amazon.awssdk.core.SdkServiceClientConfiguration;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleWithWebIdentityCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.trustedidentitypropagation.internal.IdentityAwareCredentialsProvider;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.Validate;
import software.amazon.awssdk.utils.builder.CopyableBuilder;
import software.amazon.awssdk.utils.builder.ToCopyableBuilder;


@SdkPublicApi // Plugin Best-Practice: Plugins should be marked as @SdkPublicApis.
@ThreadSafe // Plugin Best-Practice: Plugins should be thread-safe (and marked as such)
@Immutable // Plugin Best-Practice: Plugins should be immutable (and marked as such)
public class TrustedIdentityPropagationPlugin implements SdkPlugin,
    ToCopyableBuilder<TrustedIdentityPropagationPlugin.Builder, TrustedIdentityPropagationPlugin> {

    // Plugin Best-Practice: Use the AWS SDK's facade for logging.
    private static final Logger LOGGER = Logger.loggerFor(TrustedIdentityPropagationPlugin.class);

    /**
     * Custom OIDC client with customer-defined configurations. If not provided, an OIDC client
     * using default configurations will be instantiated and used.
     */
    private final SsoOidcClient ssoOidcClient;
    /**
     * Custom STS client with customer-defined configurations, used to assume `accessRoleArn` with
     * the user's identity context. If not provided, an STS client usin default configurations will
     * be instantiated and used.
     */
    private final StsClient stsClient;
    private final List<AutoCloseable> resourcesToClose;

    /**
     * The unique identifier string for the client or application. This value is an application ARN
     * that has OAuth grants configured.
     */
    private final String applicationArn;

    /**
     * An IAM role ARN which will be assumed by the plugin with the user's identity context.
     */
    private final String accessRoleArn; // IAM role to assume
    /**
     * A function that the customer implements which obtains an JSON web token from their external
     * identity provider.
     */
    private final Supplier<String> webTokenProvider; // JWT token from external IdP

    /**
     * An IAM role ARN which will be assumed with `AssumeRoleWithWebIdentity` so that the OIDC and
     * STS clients can be bootstrapped without a default credentials provider.
     * <p>
     * This field is optional. If this is not provided, the value of the `accessRoleArn` parameter
     * will be used.
     */
    private final String applicationRoleArn;

    private TrustedIdentityPropagationPlugin(Builder builder) {

        Validate.notNull(builder.applicationArn, "Application Arn must be provided.");
        Validate.notNull(builder.accessRoleArn, "Access Role Arn must be provided.");
        Validate.notNull(builder.webTokenProvider, "ID token supplier must be provided.");

        this.resourcesToClose = new ArrayList<>();

        this.applicationArn = builder.applicationArn;
        this.accessRoleArn = builder.accessRoleArn;
        this.webTokenProvider = builder.webTokenProvider;
        this.applicationRoleArn = builder.applicationRoleArn;

        this.ssoOidcClient = Validate.getOrDefault(builder.ssoOidcClient,
            getSsoOidcClientSupplier());

        this.stsClient = Validate.getOrDefault(builder.stsClient, getStsClientSupplier());

    }

    private Supplier<StsClient> getStsClientSupplier() {
        return () -> {
            StsClient client = StsClient.builder()
                .credentialsProvider(AnonymousCredentialsProvider.create()).build();
            resourcesToClose.add(client);
            return client;
        };
    }

    private Supplier<SsoOidcClient> getSsoOidcClientSupplier() {
        return () -> getSsoOidcClient();
    }

    private SsoOidcClient getSsoOidcClient() {
        StsClient noAuthStsClient = StsClient.builder()
            .credentialsProvider(AnonymousCredentialsProvider.create()).build();
        IdentityProvider credentialsProvider =
            StsAssumeRoleWithWebIdentityCredentialsProvider.builder()
                .stsClient(noAuthStsClient)
                .refreshRequest(
                    AssumeRoleWithWebIdentityRequest.builder()
                        .webIdentityToken(webTokenProvider.get())
                        .roleArn(
                            applicationRoleArn != null ? applicationRoleArn : accessRoleArn)
                        .roleSessionName(getBootstrapSessionName(applicationArn)).build())
                .build();
        SsoOidcClient client = SsoOidcClient.builder()
            .credentialsProvider(credentialsProvider).build();
        resourcesToClose.add(noAuthStsClient);
        resourcesToClose.add(client);
        return client;
    }


    public static TrustedIdentityPropagationPlugin create() {
        return new TrustedIdentityPropagationPlugin(builder());
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public void configureClient(SdkServiceClientConfiguration.Builder sdkConfiguration) {
        if (!(sdkConfiguration instanceof AwsServiceClientConfiguration.Builder)) {
            // This isn't an AWS client. Do nothing.
            return;
        }
        AwsServiceClientConfiguration.Builder awsConfiguration = (AwsServiceClientConfiguration.Builder) sdkConfiguration;

        IdentityAwareCredentialsProvider identityAwareCredentialsProvider = new IdentityAwareCredentialsProvider(
            stsClient, ssoOidcClient, webTokenProvider, applicationArn, accessRoleArn);

        awsConfiguration.credentialsProvider(identityAwareCredentialsProvider);

    }

    @Override
    public void close() {
        resourcesToClose.forEach(resource -> IoUtils.closeQuietly(resource, null));
    }

    @Override
    public Builder toBuilder() {
        return builder().accessRoleArn(accessRoleArn).applicationArn(applicationArn)
            .webTokenProvider(webTokenProvider).applicationRoleArn(applicationRoleArn)
            .ssoOidcClient(ssoOidcClient).stsClient(stsClient);
    }

    @Override
    public TrustedIdentityPropagationPlugin copy(Consumer<? super Builder> modifier) {
        Builder builder = toBuilder();
        modifier.accept(builder);
        return builder.build();
    }

    @SdkPublicApi
    @NotThreadSafe
    @Mutable
    public static class Builder implements
        CopyableBuilder<Builder, TrustedIdentityPropagationPlugin> {

        private String applicationArn;
        private String accessRoleArn;
        private Supplier<String> webTokenProvider;

        private String applicationRoleArn;
        private StsClient stsClient;
        private SsoOidcClient ssoOidcClient;

        private Builder() {
        }

        public Builder webTokenProvider(Supplier<String> webTokenProvider) {
            this.webTokenProvider = webTokenProvider;
            return this;
        }

        public Builder applicationArn(String applicationArn) {
            this.applicationArn = applicationArn;
            return this;
        }

        public Builder applicationRoleArn(String applicationRoleArn) {
            this.applicationRoleArn = applicationRoleArn;
            return this;
        }

        public Builder idTokenSupplier(Supplier<String> idTokenSupplier) {
            this.webTokenProvider = idTokenSupplier;
            return this;
        }

        public Builder accessRoleArn(String accessRoleArn) {
            this.accessRoleArn = accessRoleArn;
            return this;
        }

        public Builder stsClient(StsClient stsClient) {
            this.stsClient = stsClient;
            return this;
        }

        public Builder ssoOidcClient(SsoOidcClient ssoOidcClient) {
            this.ssoOidcClient = ssoOidcClient;
            return this;
        }

        public TrustedIdentityPropagationPlugin build() {
            return new TrustedIdentityPropagationPlugin(this);
        }
    }
}
