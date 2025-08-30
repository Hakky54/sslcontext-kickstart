/*
 * Copyright 2019 Thunderberry.
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
package nl.altindag.ssl.apache5.util;

import nl.altindag.ssl.SSLFactory;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;

/**
 * @author Hakan Altindag
 */
public final class Apache5SslUtils {

    private Apache5SslUtils() {}

    public static TlsStrategy toTlsStrategy(SSLFactory sslFactory) {
        return createClientTlsStrategy(sslFactory);
    }

    public static TlsSocketStrategy toTlsSocketStrategy(SSLFactory sslFactory) {
        return createClientTlsStrategy(sslFactory);
    }

    private static DefaultClientTlsStrategy createClientTlsStrategy(SSLFactory sslFactory) {
        return new DefaultClientTlsStrategy(
                sslFactory.getSslContext(),
                sslFactory.getSslParameters().getProtocols(),
                sslFactory.getSslParameters().getCipherSuites(),
                SSLBufferMode.STATIC,
                sslFactory.getHostnameVerifier()
        );
    }
}
