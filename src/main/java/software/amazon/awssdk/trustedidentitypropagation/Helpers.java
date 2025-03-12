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

public final class Helpers {

    private Helpers() {
        throw new AssertionError("Helpers utility class - cannot be instantiated");
    }

    public static String getAppplicationIdFromArn(String applicationArn) {
        if (applicationArn == null || applicationArn.isEmpty()) {
            return null;
        }
        String[] parts = applicationArn.split("/");
        return parts.length > 0 ? parts[parts.length - 1] : null;
    }

    public static String getBootstrapSessionName(String applicationArn) {
        return "TIPSDKPluginSession-".concat(getAppplicationIdFromArn(applicationArn));
    }

    public static String getIdentityEnhancedSessionName(String applicationArn) {
        return "TIPSDKPluginIdentityEnhancedSession-".concat(
            getAppplicationIdFromArn(applicationArn));
    }

}
