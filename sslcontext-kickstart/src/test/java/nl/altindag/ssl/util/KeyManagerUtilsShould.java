/*
 * Copyright 2019-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericKeyManagerException;
import nl.altindag.ssl.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.X509KeyManagerWrapper;
import nl.altindag.ssl.model.KeyStoreHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void createKeyManagerWithKeyStoreAndCustomAlgorithm() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerWithKeyStoreHolders() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStoreHolderOne, keyStoreHolderTwo);

        assertThat(keyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
    }

    @Test
    void createKeyManagerWithCustomSecurityProviderName() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerWithCustomSecurityProvider() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        Provider sunJsseSecurityProvider = Security.getProvider("SunJSSE");

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm(), sunJsseSecurityProvider);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void wrapIfNeeded() {
        X509KeyManager keyManager = mock(X509KeyManager.class);
        X509ExtendedKeyManager extendedKeyManager = KeyManagerUtils.wrapIfNeeded(keyManager);

        assertThat(extendedKeyManager).isInstanceOf(X509KeyManagerWrapper.class);
    }

    @Test
    void doNotWrapWhenInstanceIsX509ExtendedKeyManager() {
        X509ExtendedKeyManager keyManager = mock(X509ExtendedKeyManager.class);
        X509ExtendedKeyManager extendedKeyManager = KeyManagerUtils.wrapIfNeeded(keyManager);

        assertThat(extendedKeyManager)
                .isEqualTo(keyManager)
                .isNotInstanceOf(X509KeyManagerWrapper.class);
    }

    @Test
    void combineMultipleKeyManagersIntoOne() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);

        assertThat(combinedKeyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
    }

    @Test
    void unwrapCombinedKeyManagersAndRecombineIntoSingleBaseKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);
        X509ExtendedKeyManager combinedCombinedKeyManager = KeyManagerUtils.combine(combinedKeyManager, keyManagerOne, keyManagerTwo);

        assertThat(combinedKeyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
        assertThat(combinedCombinedKeyManager).isInstanceOf(CompositeX509ExtendedKeyManager.class);
        assertThat(((CompositeX509ExtendedKeyManager) combinedKeyManager).size()).isEqualTo(2);
        assertThat(((CompositeX509ExtendedKeyManager) combinedCombinedKeyManager).size()).isEqualTo(4);
    }

    @Test
    void createKeyManagerFactory() {
        X509ExtendedKeyManager keyManager = mock(X509ExtendedKeyManager.class);
        KeyManagerFactory keyManagerFactory = KeyManagerUtils.createKeyManagerFactory(keyManager);

        assertThat(keyManagerFactory).isNotNull();
        assertThat(keyManagerFactory.getKeyManagers()).containsExactly(keyManager);
    }

    @Test
    void createKeyManagerFromMultipleKeyManagers() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withKeyManager(keyManagerOne)
                .withKeyManager(keyManagerTwo)
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromMultipleKeyManagersUsingVarArgs() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withKeyManagers(keyManagerOne, keyManagerTwo)
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromMultipleKeyManagersUsingList() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withKeyManagers(Arrays.asList(keyManagerOne, keyManagerTwo))
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromMultipleKeyStoreHoldersAsVarArgs() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentities(keyStoreHolderOne, keyStoreHolderTwo)
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromMultipleKeyStoreHoldersAsList() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentities(Arrays.asList(keyStoreHolderOne, keyStoreHolderTwo))
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromAMultipleKeyStores() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentity(identityTwo, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromKeyStoreContainingMultipleKeysWithDifferentPasswords() throws KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "identity-with-multiple-keys.jks", IDENTITY_PASSWORD);

        assertThat(identity.size()).isEqualTo(2);

        assertThat(identity.containsAlias("kaiba")).isTrue();
        assertThat(identity.isKeyEntry("kaiba")).isTrue();

        assertThat(identity.containsAlias("yugioh")).isTrue();
        assertThat(identity.isKeyEntry("yugioh")).isTrue();


        Map<String, char[]> aliasToPassword = new HashMap<>();
        aliasToPassword.put("kaiba", "kazuki".toCharArray());
        aliasToPassword.put("yugioh", "takahashi".toCharArray());

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, aliasToPassword);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void toArray() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        X509ExtendedKeyManager[] keyManagers = KeyManagerUtils.toArray(keyManager);
        assertThat(keyManagers)
                .hasSize(1)
                .contains(keyManager);
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerFromKeyStoreWhichDoesNotHaveMatchingAlias() throws KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "identity-with-multiple-keys.jks", IDENTITY_PASSWORD);

        assertThat(identity.size()).isEqualTo(2);

        assertThat(identity.containsAlias("Jessie")).isFalse();
        assertThat(identity.containsAlias("James")).isFalse();


        Map<String, char[]> aliasToPassword = new HashMap<>();
        aliasToPassword.put("Jessie", "team-rocket".toCharArray());
        aliasToPassword.put("James", "team-rocket".toCharArray());

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, aliasToPassword))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("Could not create any KeyManager from the given KeyStore, Alias and Password");
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerFromKeyStoreWithIncorrectKeyPassword() throws KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "identity-with-multiple-keys.jks", IDENTITY_PASSWORD);

        assertThat(identity.size()).isEqualTo(2);

        assertThat(identity.containsAlias("kaiba")).isTrue();
        assertThat(identity.isKeyEntry("kaiba")).isTrue();

        assertThat(identity.containsAlias("yugioh")).isTrue();
        assertThat(identity.isKeyEntry("yugioh")).isTrue();


        Map<String, char[]> aliasToPassword = new HashMap<>();
        aliasToPassword.put("kaiba", "team-rocket".toCharArray());
        aliasToPassword.put("yugioh", "team-rocket".toCharArray());

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, aliasToPassword))
                .isInstanceOf(GenericKeyManagerException.class);
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerWithIncorrectKeyPassword() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        char[] keyPassword = "no-password".toCharArray();
        String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, keyPassword, keyManagerFactoryAlgorithm))
                .isInstanceOf(GenericKeyManagerException.class);
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerWithInvalidAlgorithm() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, "NONE"))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: NONE KeyManagerFactory not available");
    }

    @Test
    void throwExceptionWhenCreatingKeyManagerWithInvalidSecurityProviderName() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, keyManagerFactoryAlgorithm, "test"))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("java.security.NoSuchProviderException: no such provider: test");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheKeyManagerFactoryAlgorithm() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, keyManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: SunX509 for provider SUN");
    }

    @Test
    void throwExceptionWhenUnsupportedKeyManagerIsProvidedWhenSwappingKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.swapKeyManager(keyManagerOne, keyManagerTwo))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("The baseKeyManager is from the instance of [sun.security.ssl.SunX509KeyManagerImpl] " +
                        "and should be an instance of [nl.altindag.ssl.keymanager.HotSwappableX509ExtendedKeyManager].");
    }

    @Test
    void throwExceptionWhenUnsupportedKeyManagerIsProvidedWhenSwappingKeyManagerWithANewKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager baseKeyManager = KeyManagerUtils.createSwappableKeyManager(KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD));
        X509ExtendedKeyManager newKeyManager = KeyManagerUtils.createSwappableKeyManager(KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD));

        assertThatThrownBy(() -> KeyManagerUtils.swapKeyManager(baseKeyManager, newKeyManager))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("The newKeyManager should not be an instance of [nl.altindag.ssl.keymanager.HotSwappableX509ExtendedKeyManager]");
    }

}
