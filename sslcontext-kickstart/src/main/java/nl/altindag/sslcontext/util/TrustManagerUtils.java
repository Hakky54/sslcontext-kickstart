package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.trustmanager.CompositeX509ExtendedTrustManager;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509ExtendedTrustManager combine(X509ExtendedTrustManager... trustManagers) {
        return combine(Arrays.asList(trustManagers));
    }

    public static X509ExtendedTrustManager combine(List<? extends X509ExtendedTrustManager> trustManagers) {
        return CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(trustManagers)
                .build();
    }

    public static X509ExtendedTrustManager createTrustManagerWithJdkTrustedCertificates() {
        return createTrustManager((KeyStore) null);
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStoreHolder... trustStoreHolders) {
        return Arrays.stream(trustStoreHolders)
                .map(KeyStoreHolder::getKeyStore)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore... trustStores) {
        return Arrays.stream(trustStores)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore) {
        return createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String algorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(trustStore);

            return Arrays.stream(trustManagerFactory.getTrustManagers())
                    .filter(trustManager -> trustManager instanceof X509ExtendedTrustManager)
                    .map(trustManager -> (X509ExtendedTrustManager) trustManager)
                    .findFirst()
                    .orElseThrow(() -> new GenericKeyStoreException("Could not create a TrustManager with the provided TrustStore and TrustManager algorithm"));

        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new GenericSecurityException(e);
        }
    }

}
