package nl.altindag.sslcontext.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import nl.altindag.sslcontext.CompositeX509TrustManager;

public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509TrustManager combine(X509TrustManager... trustManagers) {
        return CompositeX509TrustManager.builder()
                                 .withX509TrustManagers(Arrays.asList(trustManagers))
                                 .build();
    }

    public static X509TrustManager createTrustManagerWithJdkTrustedCertificates() {
        return createTrustManager(null);
    }

    public static X509TrustManager createTrustManager(KeyStore trustStore) {
        return createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509TrustManager createTrustManager(KeyStore trustStore, String algorithm) {
        try {
            TrustManagerFactory trustManagerFactory;
            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(trustStore);

            return Arrays.stream(trustManagerFactory.getTrustManagers())
                         .filter(trustManager -> trustManager instanceof X509TrustManager)
                         .map(trustManager -> (X509TrustManager) trustManager)
                         .findFirst()
                         .orElseThrow(() -> new RuntimeException("BOOOOM!"));

        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
