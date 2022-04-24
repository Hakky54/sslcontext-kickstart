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
import nl.altindag.ssl.socket.CompositeSSLServerSocketFactory;
import nl.altindag.ssl.socket.CompositeSSLSocketFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author Hakan Altindag
 */
public final class SSLSocketUtils {

    private SSLSocketUtils() {}

    public static SSLSocketFactory createSslSocketFactory(SSLContext sslContext, SSLParameters sslParameters) {
        return new CompositeSSLSocketFactory(sslContext.getSocketFactory(), sslParameters);
    }

    public static SSLSocketFactory createSslSocketFactory(SSLSocketFactory sslSocketFactory, SSLParameters sslParameters) {
        return new CompositeSSLSocketFactory(sslSocketFactory, sslParameters);
    }

    public static SSLSocketFactory createUnsafeSslSocketFactory() {
        return SSLFactory.builder()
                .withUnsafeTrustMaterial()
                .build()
                .getSslSocketFactory();
    }

    public static SSLServerSocketFactory createSslServerSocketFactory(SSLContext sslContext, SSLParameters sslParameters) {
        return new CompositeSSLServerSocketFactory(sslContext.getServerSocketFactory(), sslParameters);
    }

    public static SSLServerSocketFactory createSslServerSocketFactory(SSLServerSocketFactory sslServerSocketFactory, SSLParameters sslParameters) {
        return new CompositeSSLServerSocketFactory(sslServerSocketFactory, sslParameters);
    }

}
