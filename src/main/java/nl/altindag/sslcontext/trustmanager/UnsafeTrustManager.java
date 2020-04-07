package nl.altindag.sslcontext.trustmanager;

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
 * <br>
 * Suppressed warning: java:S4830 - "Server certificates should be verified during SSL/TLS connections"
 *                                  This TrustManager doesn't validate certificates and should not be used at production.
 *                                  It is just meant to be used for testing purposes and it is designed not to verify server certificates.
 */
@SuppressWarnings("java:S4830")
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
