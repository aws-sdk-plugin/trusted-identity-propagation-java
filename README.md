## TRUSTED IDENTITY PROPGATION PLUGIN FOR AWS JAVA SDK 2.0

Trusted identity propagation enables AWS services to grant permissions based on user attributes such as group associations, add context to an IAM role identifying the user requesting access to AWS resources, and propagate this context to other AWS services.

TRUSTED IDENTITY PROPGATION PLUGIN provides the functionality to exchange an ID token issued by a trusted token issuer for an IdC token and pass it to AWS Services (e.g., S3 bucket) that use it to make authorization decisions.

### Things to Know

---

* AWS SDK Java 2.0 is built on Java 8
* Maven is used as the build and dependency management system

### Contributions

---
* Use [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow) to commit/review/collaborate on changes
* After a PR is approved/merged, please delete the PR branch both remotely and locally

### Building From Source

---
Once you check out the code from GitHub, you can build it using the following commands.

Linux:

```./mvnw clean install```

Windows:

```./mvnw.cmd clean install```
### USING THE PLUGIN

---

The recommended way to use the TRUSTED IDENTITY PROPGATION PLUGIN for Java in your project is to consume it from Maven Central


```
 <dependency>
    <groupId>software.amazon.awsidentity.trustedIdentityPropagation</groupId>
    <artifactId>aws-sdk-java-trustedIdentityPropagation-java-plugin</artifactId>
    <version>replace with latest version</version>
</dependency>
```

TODO: Cherry pick from public documentation once its ready

### Turn on metrics

The plugin integrates with the Metrics publisher specified on the STS and SsoOidc Clients and does not require any separate metrics publisher to be defined during the plugin creation.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
