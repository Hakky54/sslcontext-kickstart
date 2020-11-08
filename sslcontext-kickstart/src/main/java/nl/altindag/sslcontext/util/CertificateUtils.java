package nl.altindag.sslcontext.util;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.UUID;

public final class CertificateUtils {

    private CertificateUtils() {}

    public static String generateAlias(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName();
        } else {
            return UUID.randomUUID().toString();
        }
    }

}
