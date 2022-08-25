/*
 * Copyright 2019-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.util;

import nl.altindag.ssl.hostnameverifier.BasicHostNameVerifier;
import nl.altindag.ssl.hostnameverifier.FenixHostnameVerifier;
import nl.altindag.ssl.hostnameverifier.UnsafeHostNameVerifier;

import javax.net.ssl.HostnameVerifier;

/**
 * @author Hakan Altindag
 */
public final class HostnameVerifierUtils {

    private HostnameVerifierUtils() {}

    /**
     * Creates a basic hostname verifier which validates the hostname against the peer host from the ssl session.
     * This basic hostname verifier provides minimal security. It is recommended to use {@link HostnameVerifierUtils#createFenix()}
     */
    public static HostnameVerifier createBasic() {
        return BasicHostNameVerifier.getInstance();
    }

    /**
     * Creates an unsafe hostname verifier which does not validate the hostname at all.
     * This hostname verifier is unsafe and should be avoided
     */
    public static HostnameVerifier createUnsafe() {
        return UnsafeHostNameVerifier.getInstance();
    }

    /**
     * Creates a fenix hostname verifier which validates the hostname against the SAN field of the peer certificate.
     */
    public static HostnameVerifier createFenix() {
        return FenixHostnameVerifier.getInstance();
    }

}
