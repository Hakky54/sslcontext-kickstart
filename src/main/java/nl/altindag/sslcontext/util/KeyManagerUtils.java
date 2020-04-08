package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.sslcontext.model.KeyStoreHolder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.List;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

public final class KeyManagerUtils {

    private KeyManagerUtils() {}

    public static X509ExtendedKeyManager combine(X509ExtendedKeyManager... keyManagers) {
        return combine(Arrays.asList(keyManagers));
    }

    public static X509ExtendedKeyManager combine(List<X509ExtendedKeyManager> keyManagers) {
        return CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagers)
                .build();
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStoreHolder... keyStoreHolders) {
        return Arrays.stream(keyStoreHolders)
                .map(keyStoreHolder -> createKeyManager(keyStoreHolder.getKeyStore(), keyStoreHolder.getKeyStorePassword()))
                .collect(collectingAndThen(toList(), KeyManagerUtils::combine));
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyStorePassword) {
        return createKeyManager(keyStore, keyStorePassword, KeyManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyStorePassword, String algorithm) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            keyManagerFactory.init(keyStore, keyStorePassword);

            return Arrays.stream(keyManagerFactory.getKeyManagers())
                    .filter(keyManager -> keyManager instanceof X509ExtendedKeyManager)
                    .map(keyManager -> (X509ExtendedKeyManager) keyManager)
                    .findFirst()
                    .orElseThrow(() -> new GenericKeyStoreException("Could not create a KeyManager with the provided keyStore and password"));

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new GenericSecurityException(e);
        }
    }

}
