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
package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLParameters;

/**
 * @author Hakan Altindag
 */
public final class JettySslUtils {

    private JettySslUtils() {}

    /**
     * Creates a basic {@link SslContextFactory Client SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory}
     */
    public static SslContextFactory.Client forClient(SSLFactory sslFactory) {
        SslContextFactory.Client sslContextFactory = createSslContextFactory(sslFactory, new SslContextFactory.Client());
        sslContextFactory.setHostnameVerifier(sslFactory.getHostnameVerifier());
        return sslContextFactory;
    }

    /**
     * Creates a basic {@link SslContextFactory Server SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory}
     */
    public static SslContextFactory.Server forServer(SSLFactory sslFactory) {
        SslContextFactory.Server sslContextFactory = createSslContextFactory(sslFactory, new SslContextFactory.Server());
        SSLParameters sslParameters = sslFactory.getSslParameters();
        if (sslParameters.getNeedClientAuth()) {
            sslContextFactory.setNeedClientAuth(true);
        }
        if (sslParameters.getWantClientAuth()) {
            sslContextFactory.setWantClientAuth(true);
        }
        return sslContextFactory;
    }

    private static <T extends SslContextFactory> T createSslContextFactory(SSLFactory sslFactory, T sslContextFactory) {
        sslContextFactory.setSslContext(sslFactory.getSslContext());
        SSLParameters sslParameters = sslFactory.getSslParameters();
        sslContextFactory.setIncludeProtocols(sslParameters.getProtocols());
        sslContextFactory.setIncludeCipherSuites(sslParameters.getCipherSuites());
        return sslContextFactory;
    }

}
