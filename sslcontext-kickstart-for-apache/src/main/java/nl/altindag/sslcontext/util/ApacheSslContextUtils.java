package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.SSLFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

import java.util.Objects;

public final class ApacheSslContextUtils {

    public static LayeredConnectionSocketFactory toLayeredConnectionSocketFactory(SSLFactory sslFactory) {
        Objects.requireNonNull(sslFactory.getSslContext());

        return new SSLConnectionSocketFactory(
                sslFactory.getSslContext(),
                sslFactory.getSslContext().getSupportedSSLParameters().getProtocols(),
                sslFactory.getSslContext().getSupportedSSLParameters().getCipherSuites(),
                sslFactory.getHostnameVerifier()
        );
    }

}
