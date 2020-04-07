package nl.altindag.sslcontext.keymanager;

import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.util.KeyManagerUtils;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class CompositeX509KeyManagerShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void createCompositeX509KeyManagerFromKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getKeyManagers()).hasSize(2);
        assertThat(keyManager.getPrivateKey("dummy-client")).isNotNull();
        assertThat(keyManager.getPrivateKey("another-server")).isNotNull();
    }

    @Test
    public void returnNullForUnknownAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getPrivateKey("TOGG")).isNull();
    }

    @Test
    public void returnCertificateChain() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
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
    public void returnNullForUnknownAliasWhenGettingCertificateChain() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withIdentities(
                        new KeyStoreHolder(identityOne, IDENTITY_PASSWORD),
                        new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD))
                .build();

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getCertificateChain("TOGG")).isNull();
    }

    @Test
    public void getServerAliases() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(Arrays.asList(keyManagerOne, keyManagerTwo))
                .build();

        String[] aliases = keyManager.getServerAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    public void getClientAliases() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String[] aliases = keyManager.getClientAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    public void chooseFirstServerAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    public void chooseFirstServerAliasWithMatchingKeyTypeWithDifferentOrderOfInitializationOfTheKeyManager() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    public void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingServerAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseServerAlias("ECDSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    public void chooseFirstClientAliasWithMatchingKeyType() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    public void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingClientAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509KeyManager keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(keyManagerTwo, keyManagerOne)
                .build();

        String alias = keyManager.chooseClientAlias(new String[]{"ECDSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

}
