## Trusted Identity Propagation Plugin for AWS SDK for Java 2.0

Trusted identity propagation enables AWS services to grant permissions based on user attributes such as group associations, add context to an IAM role identifying the user requesting access to AWS resources, and propagate this context to other AWS services.

This plugin provides the functionality to exchange an Id token issued by a trusted token issuer for an IAM Identity Center token and pass it to AWS services (e.g., AWS S3, Amazon Q) that use it to make authorization decisions.

### Things to Know

---

* AWS SDK Java 2.0 is built on Java 8
* Maven is used as the build and dependency management system

### Contributions

---
* Use [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow) to commit/review/collaborate on changes
* After a PR is approved/merged, please delete the PR branch both remotely and locally

### Using the Plugin

---

The recommended way to use the TRUSTED IDENTITY PROPGATION PLUGIN for Java in your project is to consume it from Maven Central


```
 <dependency>
    <groupId>software.amazon.awsidentity.trustedIdentityPropagation</groupId>
    <artifactId>aws-sdk-java-trustedIdentityPropagation-java-plugin</artifactId>
    <version>replace with latest version</version>
</dependency>
```

## Usage

Initialize the plugin and provide it as an extension to the SDK that you want to use trusted identity propagation with.
``` java 
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

```

## Install from source

The plugin has been published to Maven and can be installed as described above. If you want to play with the latest version, you can build from source as follows.

1. Clone this repository locally
```bash
git clone https://github.com/aws-sdk-plugin/trusted-identity-propagation-java.git
```

2. Install dependencies and build the plugin
```bash
./mvnw clean install
```

3. Pack the plugin
```bash
./mvnw clean package
```

### Turn on metrics

The plugin integrates with the Metrics publisher specified on the STS and SsoOidc Clients and does not require any separate metrics publisher to be defined during the plugin creation.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
