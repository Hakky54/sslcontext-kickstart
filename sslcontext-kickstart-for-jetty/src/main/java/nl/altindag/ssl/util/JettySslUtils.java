/*
 * Copyright 2019-2021 the original author or authors.
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
import org.eclipse.jetty.util.ssl.SslContextFactory;

/**
 * @author Hakan Altindag
 */
public final class JettySslUtils {

    private JettySslUtils() {}

    /**
     * Creates a basic {@link SslContextFactory.Client Client SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory.Client}
     */
    public static SslContextFactory.Client forClient(SSLFactory sslFactory) {
        return createSslContextFactory(sslFactory, new SslContextFactory.Client());
    }

    /**
     * Creates a basic {@link SslContextFactory.Server Server SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory.Server}
     */
    public static SslContextFactory.Server forServer(SSLFactory sslFactory) {
        return createSslContextFactory(sslFactory, new SslContextFactory.Server());
    }

    private static <T extends SslContextFactory> T createSslContextFactory(SSLFactory sslFactory, T sslContextFactory) {
        sslContextFactory.setSslContext(sslFactory.getSslContext());
        sslContextFactory.setIncludeProtocols(sslFactory.getSslParameters().getProtocols());
        sslContextFactory.setIncludeCipherSuites(sslFactory.getSslParameters().getCipherSuites());
        sslContextFactory.setHostnameVerifier(sslFactory.getHostnameVerifier());

        return sslContextFactory;
    }

}
