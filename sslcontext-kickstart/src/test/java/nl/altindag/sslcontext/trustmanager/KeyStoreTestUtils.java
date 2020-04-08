package nl.altindag.sslcontext.trustmanager;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class KeyStoreTestUtils {

    static X509Certificate[] getTrustedX509Certificates(KeyStore trustStore) throws KeyStoreException {
        List<X509Certificate> certificates = new ArrayList<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            Certificate certificate = trustStore.getCertificate(aliases.nextElement());
            if (certificate instanceof X509Certificate) {
                certificates.add((X509Certificate) certificate);
            }
        }

        return certificates.toArray(new X509Certificate[0]);
    }

}
