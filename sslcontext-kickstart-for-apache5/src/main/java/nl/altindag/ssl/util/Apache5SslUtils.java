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

import nl.altindag.ssl.SSLFactory;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.nio.ssl.BasicClientTlsStrategy;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;

/**
 * @author Hakan Altindag
 */
public final class Apache5SslUtils {

    private Apache5SslUtils() {}

    public static LayeredConnectionSocketFactory toSocketFactory(SSLFactory sslFactory) {
        return new SSLConnectionSocketFactory(
                sslFactory.getSslContext(),
                sslFactory.getSslParameters().getProtocols(),
                sslFactory.getSslParameters().getCipherSuites(),
                sslFactory.getHostnameVerifier()
        );
    }

    public static TlsStrategy toTlsStrategy(SSLFactory sslFactory) {
        return new BasicClientTlsStrategy(sslFactory.getSslContext());
    }

}
