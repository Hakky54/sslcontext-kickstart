package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

public final class Apache4SslUtils {

    private Apache4SslUtils() {}

    public static LayeredConnectionSocketFactory toSocketFactory(SSLFactory sslFactory) {
        return new SSLConnectionSocketFactory(
                sslFactory.getSslContext(),
                sslFactory.getSslParameters().getProtocols(),
                sslFactory.getSslParameters().getCipherSuites(),
                sslFactory.getHostnameVerifier()
        );
    }

}
