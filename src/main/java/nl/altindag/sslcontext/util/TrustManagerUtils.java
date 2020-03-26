package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.trustmanager.CompositeX509TrustManager;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509TrustManager combine(X509TrustManager... trustManagers) {
        return combine(Arrays.asList(trustManagers));
    }

    public static X509TrustManager combine(List<X509TrustManager> trustManagers) {
        return CompositeX509TrustManager.builder()
                .withTrustManagers(trustManagers)
                .build();
    }

    public static X509TrustManager createTrustManagerWithJdkTrustedCertificates() {
        return createTrustManager((KeyStore) null);
    }

    public static X509TrustManager createTrustManager(KeyStoreHolder... trustStoreHolders) {
        return Arrays.stream(trustStoreHolders)
                .map(KeyStoreHolder::getKeyStore)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509TrustManager createTrustManager(KeyStore... trustStores) {
        return Arrays.stream(trustStores)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509TrustManager createTrustManager(KeyStore trustStore) {
        return createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509TrustManager createTrustManager(KeyStore trustStore, String algorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(trustStore);

            return Arrays.stream(trustManagerFactory.getTrustManagers())
                    .filter(trustManager -> trustManager instanceof X509TrustManager)
                    .map(trustManager -> (X509TrustManager) trustManager)
                    .findFirst()
                    .orElseThrow(() -> new GenericKeyStoreException("Could not create a TrustManager with the provided trustStore"));

        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new GenericSecurityException(e);
        }
    }

}
