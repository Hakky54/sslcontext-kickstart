package nl.altindag.sslcontext.util;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import nl.altindag.sslcontext.SSLFactory;

import javax.net.ssl.X509ExtendedKeyManager;
import java.util.Arrays;

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
        SslContextBuilder sslContextBuilder = SslContextBuilder.forClient()
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
        sslFactory.getKeyManager().ifPresent(sslContextBuilder::keyManager);
        sslFactory.getTrustManager().ifPresent(sslContextBuilder::trustManager);

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
        X509ExtendedKeyManager keyManager = sslFactory.getKeyManager()
                .orElseThrow(NullPointerException::new);

        SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(keyManager)
                .ciphers(Arrays.asList(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites()), SupportedCipherSuiteFilter.INSTANCE)
                .protocols(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
        sslFactory.getTrustManager().ifPresent(sslContextBuilder::trustManager);

        return sslContextBuilder;
    }

}
