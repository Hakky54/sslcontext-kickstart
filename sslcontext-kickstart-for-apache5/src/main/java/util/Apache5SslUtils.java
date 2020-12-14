package util;

import nl.altindag.ssl.SSLFactory;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.nio.ssl.BasicClientTlsStrategy;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;

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
