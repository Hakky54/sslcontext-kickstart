package nl.altindag.sslcontext.util;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import nl.altindag.sslcontext.SSLFactory;

import java.util.Arrays;
import java.util.Objects;

public final class NettySslContextUtils {

    private NettySslContextUtils() {}

    public static SslContextBuilder forClient(SSLFactory sslFactory) {
        Objects.requireNonNull(sslFactory.getSslContext());

        SslContextBuilder sslContextBuilder = SslContextBuilder.forClient()
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());

        if (sslFactory.isOneWayAuthenticationEnabled()) {
            sslContextBuilder.trustManager(sslFactory.getTrustManagerFactory());
        }

        if (sslFactory.isTwoWayAuthenticationEnabled()) {
            sslContextBuilder.keyManager(sslFactory.getKeyManagerFactory())
                    .trustManager(sslFactory.getTrustManagerFactory());
        }
        return sslContextBuilder;
    }

    public static SslContextBuilder forServer(SSLFactory sslFactory) {
        Objects.requireNonNull(sslFactory.getSslContext());
        Objects.requireNonNull(sslFactory.getKeyManagerFactory());

        return SslContextBuilder.forServer(sslFactory.getKeyManagerFactory())
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols())
                .trustManager(sslFactory.getTrustManagerFactory());
    }

}
