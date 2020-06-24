package nl.altindag.sslcontext.keymanager;

import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.util.KeyManagerUtils;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class CompositeX509ExtendedKeyManagerShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void createCompositeX509KeyManagerFromKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(keyManager.getPrivateKey("dummy-client")).isNotNull();
        assertThat(keyManager.getPrivateKey("another-server")).isNotNull();
    }

    @Test
    void returnNullForUnknownAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getPrivateKey("TOGG")).isNull();
    }

    @Test
    void returnCertificateChain() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentity(identityTwo, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);

        assertThat(keyManager.getCertificateChain("dummy-client"))
                .isNotNull()
                .isNotEmpty();

        assertThat(keyManager.getCertificateChain("another-server"))
                .isNotNull()
                .isNotEmpty();
    }

    @Test
    void returnNullForUnknownAliasWhenGettingCertificateChain() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getCertificateChain("TOGG")).isNull();
    }

    @Test
    void getServerAliases() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(Arrays.asList(keyManagerOne, keyManagerTwo))
                .build();

        String[] aliases = keyManager.getServerAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    void getClientAliases() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String[] aliases = keyManager.getClientAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    void chooseFirstServerAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstEngineServerAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseEngineServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstServerAliasWithMatchingKeyTypeWithDifferentOrderOfInitializationOfTheKeyManager() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void chooseFirstEngineServerAliasWithMatchingKeyTypeWithDifferentOrderOfInitializationOfTheKeyManager() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingServerAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseServerAlias("ECDSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingEngineServerAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseEngineServerAlias("ECDSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void chooseFirstClientAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstEngineClientAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseEngineClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingClientAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseClientAlias(new String[]{"ECDSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingEngineClientAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseEngineClientAlias(new String[]{"ECDSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

}
