package nl.altindag.ssl.trustmanager;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
interface CombinableX509ExtendedTrustManager extends X509TrustManager {

    String CERTIFICATE_EXCEPTION_MESSAGE = "None of the TrustManagers trust this certificate chain";

    List<X509ExtendedTrustManager> getTrustManagers();

    default void checkTrusted(TrustManagerConsumer callBackConsumer) throws CertificateException {
        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : getTrustManagers()) {
            try {
                callBackConsumer.checkTrusted(trustManager);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

}
