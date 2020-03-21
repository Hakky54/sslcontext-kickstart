package nl.altindag.sslcontext.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509KeyManager;

public final class KeyManagerUtils {

    private KeyManagerUtils() {}

    public static X509KeyManager combine(X509KeyManager... keyManagers) {
        return CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagers)
                .build();
    }

    public static X509KeyManager createKeyManager(KeyStore keyStore, char[] keyStorePassword) {
        return createKeyManager(keyStore, keyStorePassword, KeyManagerFactory.getDefaultAlgorithm());
    }

    public static X509KeyManager createKeyManager(KeyStore keyStore, char[] keyStorePassword, String algorithm) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            keyManagerFactory.init(keyStore, keyStorePassword);

            return Arrays.stream(keyManagerFactory.getKeyManagers())
                    .filter(trustManager -> trustManager instanceof X509KeyManager)
                    .map(keyManager -> (X509KeyManager) keyManager)
                    .findFirst()
                    .orElseThrow(() -> new GenericKeyStoreException("Could not create a KeyManager with the provided keyStore and password"));

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new GenericSecurityException(e);
        }
    }

}
