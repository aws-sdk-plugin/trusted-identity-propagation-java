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


public class Constants {

    public static final String REFRESH_TOKEN_GRANT = "refresh_token";
    public static final String JWT_BEARER_GRANT_URI = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String CONTEXT_PROVIDER_IDENTITY_CENTER = "arn:aws:iam::aws:contextProvider/IdentityCenter";

    private Constants() {
    }


}
