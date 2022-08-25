/*
 * Copyright (C) 2021 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.hostnameverifier;

import java.util.regex.Pattern;

/**
 * This HostnameCommon is copied from OkHttp library, see here for the original content:
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/commonMain/kotlin/okhttp3/internal/-HostnamesCommon.kt#L1
 */
final class HostnameCommon {

    private static final Pattern VERIFY_AS_IP_ADDRESS = Pattern.compile("([0-9a-fA-F]*:[0-9a-fA-F:.]*)|([\\d.]+)");

    private HostnameCommon() {}

    static boolean canParseAsIpAddress(String value) {
        return VERIFY_AS_IP_ADDRESS.matcher(value).matches();
    }

    /**
     * Returns true if the length is not valid for DNS (empty or greater than 253 characters), or if any
     * label is longer than 63 characters. Trailing dots are okay.
     */
    static boolean containsInvalidLabelLengths(String hostname) {
        if (hostname.length() < 1 || hostname.length() > 253) {
            return true;
        }

        int labelStart = 0;
        while (true) {
            int dot = hostname.indexOf('.', labelStart);
            int labelLength;
            if (dot == -1) {
                labelLength = hostname.length() - labelStart;
            } else {
                labelLength = dot - labelStart;
            }
            if (labelLength < 1 || labelLength > 63) {
                return true;
            }
            if (dot == -1) {
                break;
            }
            if (dot == hostname.length() - 1) {
                break; // Trailing '.' is allowed.
            }
            labelStart = dot + 1;
        }

        return false;
    }

    static boolean containsInvalidHostnameAsciiCodes(String hostname) {
        for (int i = 0; i < hostname.length(); i++) {
            char c = hostname.charAt(i);

            // The WHATWG Host parsing rules accepts some character codes which are invalid by
            // definition for OkHttp's host header checks (and the WHATWG Host syntax definition). Here
            // we rule out characters that would cause problems in host headers.
            if (c <= '\u001f' || c >= '\u007f') {
                return true;
            }

            // Check for the characters mentioned in the WHATWG Host parsing spec:
            // U+0000, U+0009, U+000A, U+000D, U+0020, "#", "%", "/", ":", "?", "@", "[", "\", and "]"
            // (excluding the characters covered above).
            if (" #%/:?@[\\]".indexOf(c) != -1) {
                return true;
            }
        }
        return false;
    }

}
