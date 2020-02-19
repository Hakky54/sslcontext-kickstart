package nl.altindag.sslcontext.trustmanager;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * An insecure {@link UnsafeTrustManager TrustManager} that trusts all X.509 certificates without any verification.
 * <p>
 * <strong>NOTE:</strong>
 * Never use this {@link UnsafeTrustManager} in production.
 * It is purely for testing purposes, and thus it is very insecure.
 * </p>
 *
 * @see InsecureTrustManagerFactory
 */
public final class UnsafeTrustManager implements X509TrustManager {

    public static final UnsafeTrustManager INSTANCE = new UnsafeTrustManager();
    private static final Logger LOGGER = LogManager.getLogger(UnsafeTrustManager.class);
    private static final X509Certificate[] EMPTY_X509_CERTIFICATES = new X509Certificate[0];

    private UnsafeTrustManager() {}

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Accepting a client certificate: [{}]", x509Certificates[0].getSubjectDN());
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Accepting a server certificate: [{}]", x509Certificates[0].getSubjectDN());
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return EMPTY_X509_CERTIFICATES;
    }

}
