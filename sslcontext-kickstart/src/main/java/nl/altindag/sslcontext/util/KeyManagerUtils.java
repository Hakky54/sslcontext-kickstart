package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.sslcontext.keymanager.X509KeyManagerWrapper;
import nl.altindag.sslcontext.model.KeyStoreHolder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
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

    public static X509ExtendedKeyManager combine(List<? extends X509ExtendedKeyManager> keyManagers) {
        return CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagers)
                .build();
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStoreHolder... keyStoreHolders) {
        return Arrays.stream(keyStoreHolders)
                .map(keyStoreHolder -> createKeyManager(keyStoreHolder.getKeyStore(), keyStoreHolder.getKeyPassword()))
                .collect(collectingAndThen(toList(), KeyManagerUtils::combine));
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword) {
        return createKeyManager(keyStore, keyPassword, KeyManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericSecurityException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm, String securityProviderName) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm, securityProviderName);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericSecurityException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm, securityProvider);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericSecurityException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, KeyManagerFactory keyManagerFactory) {
        try {
            keyManagerFactory.init(keyStore, keyPassword);
            return Arrays.stream(keyManagerFactory.getKeyManagers())
                    .filter(keyManager -> keyManager instanceof X509KeyManager)
                    .map(keyManager -> (X509KeyManager) keyManager)
                    .map(KeyManagerUtils::wrapIfNeeded)
                    .findFirst()
                    .orElseThrow(() -> new GenericKeyStoreException("Could not create a KeyManager with the provided KeyStore, password and KeyManager algorithm"));

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new GenericSecurityException(e);
        }
    }

    public static X509ExtendedKeyManager wrapIfNeeded(X509KeyManager keyManager) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            return (X509ExtendedKeyManager) keyManager;
        } else {
            return new X509KeyManagerWrapper(keyManager);
        }
    }

}
