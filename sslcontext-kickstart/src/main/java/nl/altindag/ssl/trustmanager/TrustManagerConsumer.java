package nl.altindag.ssl.trustmanager;

import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.CertificateException;

/**
 * @author Hakan Altindag
 */
@FunctionalInterface
interface TrustManagerConsumer {

    void checkTrusted(X509ExtendedTrustManager trustManager) throws CertificateException;

}
