package nl.altindag.sslcontext.util;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import nl.altindag.sslcontext.SSLFactory;

import java.util.Arrays;
import java.util.Objects;

public final class NettySslContextUtils {

    private NettySslContextUtils() {}

    /**
     * Creates a basic {@link SslContextBuilder Client SslContextBuilder}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextBuilder}
     */
    public static SslContextBuilder forClient(SSLFactory sslFactory) {
        Objects.requireNonNull(sslFactory.getSslContext());

        SslContextBuilder sslContextBuilder = SslContextBuilder.forClient()
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());

        if (sslFactory.isOneWayAuthenticationEnabled()) {
            sslContextBuilder.trustManager(sslFactory.getTrustManager());
        }

        if (sslFactory.isTwoWayAuthenticationEnabled()) {
            sslContextBuilder.keyManager(sslFactory.getKeyManager())
                    .trustManager(sslFactory.getTrustManager());
        }
        return sslContextBuilder;
    }

    /**
     * Creates a basic {@link SslContextBuilder Server SslContextBuilder}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextBuilder}
     */
    public static SslContextBuilder forServer(SSLFactory sslFactory) {
        Objects.requireNonNull(sslFactory.getSslContext());
        Objects.requireNonNull(sslFactory.getKeyManager());

        return SslContextBuilder.forServer(sslFactory.getKeyManager())
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols())
                .trustManager(sslFactory.getTrustManager());
    }

}
