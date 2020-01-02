package nl.altindag.thunderberry.sslcontext.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import nl.altindag.thunderberry.sslcontext.CompositeX509TrustManager;

public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509TrustManager[] getTrustManagers(KeyStore trustStore) {
        return new X509TrustManager[] {
                CompositeX509TrustManager.builder()
                                         .withTrustStore(trustStore)
                                         .build()
        };
    }

    public static X509TrustManager combine(X509TrustManager... trustManagers) {
        return CompositeX509TrustManager.builder()
                                 .withX509TrustManagers(Arrays.asList(trustManagers))
                                 .build();
    }

    public static X509TrustManager getJdkDefaultTrustManager() {
        return getTrustManager(null);
    }

    public static X509TrustManager getTrustManager(KeyStore keystore) {
        return getTrustManager(keystore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509TrustManager getTrustManager(KeyStore keystore, String algorithm) {
        try {
            TrustManagerFactory trustManagerFactory;
            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(keystore);

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
