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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class Helpers {

    private static final Properties POM_PROPERTIES = new Properties();

    private Helpers() {
        throw new AssertionError("Helpers utility class - cannot be instantiated");
    }

    static {
        try (InputStream input = Helpers.class.getClassLoader()
            .getResourceAsStream("pom.properties")) {
            if (input != null) {
                POM_PROPERTIES.load(input);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load pom.properties", e);
        }
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

    public static String getVersion() {
        return POM_PROPERTIES.getProperty("version");
    }


}
