package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyManagerUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void createKeyManagerWithKeyStoreAndCustomAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerWithKeyStoreHolders() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStoreHolderOne, keyStoreHolderTwo);

        assertThat(keyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerWithInvalidAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, "NONE"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: NONE KeyManagerFactory not available");
    }

    @Test
    void combineMultipleKeyManagersIntoOne() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);

        assertThat(combinedKeyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
    }

}
