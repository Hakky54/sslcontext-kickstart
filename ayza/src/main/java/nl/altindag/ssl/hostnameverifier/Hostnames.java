/*
 * Copyright (C) 2012 The Android Open Source Project
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

import nl.altindag.ssl.exception.GenericHostnameVerifierException;

import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

import static nl.altindag.ssl.hostnameverifier.HostnameCommon.containsInvalidHostnameAsciiCodes;
import static nl.altindag.ssl.hostnameverifier.HostnameCommon.containsInvalidLabelLengths;

/**
 * This HostnameVerifier is copied from OkHttp library, see here for the original content:
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/jvmMain/kotlin/okhttp3/internal/-HostnamesJvm.kt#L1
 */
final class Hostnames {

    private Hostnames() {}

    /**
     * If this is an IP address, this returns the IP address in canonical form.
     * <p>
     * Otherwise this performs IDN ToASCII encoding and canonicalize the result to lowercase. For
     * example this converts `☃.net` to `xn--n3h.net`, and `WwW.GoOgLe.cOm` to `www.google.com`.
     * `null` will be returned if the host cannot be ToASCII encoded or if the result contains
     * unsupported ASCII characters.
     */
    static String toCanonicalHost(String host) {
        String result = host;
        // If the input contains a :, it’s an IPv6 address.
        if (host.contains(":")) {
            // If the input is encased in square braces "[...]", drop 'em.
            if (host.startsWith("[" ) && host.endsWith("]")) {
                result = host.substring(1, host.length() - 1);
            }

            try {
                InetAddress inetAddress = InetAddress.getByName(result);
                return inetAddress.getHostAddress();
            } catch (UnknownHostException e) {
                throw new GenericHostnameVerifierException(e);
            }
        }

        try {
            result = IDN.toASCII(host).toLowerCase(Locale.US);
            if (result.isEmpty()) {
                return null;
            }

            if (containsInvalidHostnameAsciiCodes(result)) {
                // The IDN ToASCII result contains illegal characters.
                return null;
            } else if (containsInvalidLabelLengths(result)) {
                // The IDN ToASCII result contains invalid labels.
                return null;
            } else {
                return result;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

}
