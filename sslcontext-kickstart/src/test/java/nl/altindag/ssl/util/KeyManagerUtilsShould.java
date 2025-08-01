/*
 * Copyright 2019 Thunderberry.
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
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.keymanager.AggregatedX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.DelegatingX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.DummyX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.HotSwappableX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.InflatableX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.LoggingX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.X509KeyManagerWrapper;
import nl.altindag.ssl.model.KeyStoreHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void createKeyManagerWithKeyStoreAndCustomAlgorithm() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerWithPrivateKeyAndCertificateChain() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        PrivateKey privateKey = (PrivateKey) identity.getKey("dummy-client", "secret".toCharArray());
        Certificate[] chain = identity.getCertificateChain("dummy-client");

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(privateKey, chain);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerWithKeyStoreHolders() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStoreHolderOne, keyStoreHolderTwo);

        assertThat(keyManager).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
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

        assertThat(combinedKeyManager).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
    }

    @Test
    void unwrapCombinedKeyManagersAndRecombineIntoSingleBaseKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);
        X509ExtendedKeyManager combinedCombinedKeyManager = KeyManagerUtils.combine(combinedKeyManager, keyManagerOne, keyManagerTwo);
        X509ExtendedKeyManager combinedCombinedCombinedKeyManager = KeyManagerUtils.combine(combinedCombinedKeyManager, combinedKeyManager, keyManagerOne, keyManagerTwo);

        assertThat(combinedKeyManager).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(combinedCombinedKeyManager).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(combinedCombinedCombinedKeyManager).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(((AggregatedX509ExtendedKeyManager) combinedKeyManager).getInnerKeyManagers().size()).isEqualTo(2);
        assertThat(((AggregatedX509ExtendedKeyManager) combinedCombinedKeyManager).getInnerKeyManagers().size()).isEqualTo(4);
        assertThat(((AggregatedX509ExtendedKeyManager) combinedCombinedCombinedKeyManager).getInnerKeyManagers().size()).isEqualTo(8);
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

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentities(keyStoreHolderOne, keyStoreHolderTwo)
                .build();

        assertThat(keyManager).isNotNull();
    }

    @Test
    void createKeyManagerFromMultipleKeyStoreHoldersAsList() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyStoreHolder keyStoreHolderOne = new KeyStoreHolder(identityOne, IDENTITY_PASSWORD);
        KeyStoreHolder keyStoreHolderTwo = new KeyStoreHolder(identityTwo, IDENTITY_PASSWORD);

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
    void createLoggingKeyManagerWithKeyStore() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentity(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withLoggingKeyManager(true)
                .build();

        assertThat(keyManager).isInstanceOf(LoggingX509ExtendedKeyManager.class);
    }

    @Test
    void createLoggingKeyManagerWhichIsAlsoSwappable() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentity(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withLoggingKeyManager(true)
                .withSwappableKeyManager(true)
                .build();

        assertThat(keyManager).isInstanceOf(HotSwappableX509ExtendedKeyManager.class);
        X509ExtendedKeyManager innerKeyManager = ((HotSwappableX509ExtendedKeyManager) keyManager).getInnerKeyManager();
        assertThat(innerKeyManager).isInstanceOf(LoggingX509ExtendedKeyManager.class);
    }

    @Test
    void swapKeyManagerWhileLoggingIsEnabled() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withLoggingKeyManager(true)
                .withSwappableKeyManager(true)
                .build();

        assertThat(keyManager).isInstanceOf(HotSwappableX509ExtendedKeyManager.class);
        X509ExtendedKeyManager innerKeyManager = ((HotSwappableX509ExtendedKeyManager) keyManager).getInnerKeyManager();
        assertThat(innerKeyManager).isInstanceOf(LoggingX509ExtendedKeyManager.class);
        X509ExtendedKeyManager innerInnerKeyManager = ((LoggingX509ExtendedKeyManager) innerKeyManager).getInnerKeyManager();

        X509ExtendedKeyManager newKeyManager = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);
        KeyManagerUtils.swapKeyManager(keyManager, newKeyManager);

        X509ExtendedKeyManager newInnerKeyManager = ((HotSwappableX509ExtendedKeyManager) keyManager).getInnerKeyManager();
        assertThat(newInnerKeyManager).isInstanceOf(LoggingX509ExtendedKeyManager.class);
        X509ExtendedKeyManager newInnerInnerKeyManager = ((LoggingX509ExtendedKeyManager) newInnerKeyManager).getInnerKeyManager();
        assertThat(innerKeyManager).isNotEqualTo(newInnerInnerKeyManager);
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
    void addClientIdentityRoutesToInflatableKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.keyManagerBuilder()
                .withInflatableKeyManager(true)
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentity(identityTwo, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .build();

        KeyManagerUtils.addIdentityRoute(inflatableKeyManager, "client","https://localhost:8443/");
        KeyManagerUtils.addIdentityRoute(inflatableKeyManager, "client","https://localhost:8453/");
        Map<String, List<String>> identityRoute = KeyManagerUtils.getIdentityRoute(inflatableKeyManager);

        assertThat(identityRoute)
                .containsKey("client")
                .containsValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"));
    }

    @Test
    void overrideIdentityRoutes() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);
        KeyManagerUtils.addIdentityRoute(keyManager, "client","https://localhost:8443/", "https://localhost:8453/");
        Map<String, List<String>> identityRoute = KeyManagerUtils.getIdentityRoute(keyManager);

        assertThat(identityRoute)
                .containsKey("client")
                .containsValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"));

        KeyManagerUtils.overrideIdentityRoute(keyManager, "client", "https://localhost:9443/", "https://localhost:9453/");
        identityRoute = KeyManagerUtils.getIdentityRoute(keyManager);

        assertThat(identityRoute)
                .containsKey("client")
                .doesNotContainValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"))
                .containsValue(Arrays.asList("https://localhost:9443/", "https://localhost:9453/"));
    }

    @Test
    void addClientIdentities() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        Map<String, List<URI>> hostsToUris = new HashMap<>();
        hostsToUris.put("client", Arrays.asList(URI.create("https://localhost:8443/"), URI.create("https://localhost:8453/")));

        X509ExtendedKeyManager keyManager = KeyManagerUtils.keyManagerBuilder()
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentity(identityTwo, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentityRoute(hostsToUris)
                .build();

        Map<String, List<String>> clientIdentityRoute = KeyManagerUtils.getIdentityRoute(keyManager);

        assertThat(clientIdentityRoute)
                .containsKey("client")
                .containsValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"));
    }

    @Test
    void removeClientIdentityRoutes() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.keyManagerBuilder()
                .withInflatableKeyManager(true)
                .withIdentity(identityOne, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .withIdentity(identityTwo, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm())
                .build();

        KeyManagerUtils.addIdentityRoute(inflatableKeyManager, "client","https://localhost:8443/");
        KeyManagerUtils.addIdentityRoute(inflatableKeyManager, "client","https://localhost:8453/");
        Map<String, List<String>> identityRoute = KeyManagerUtils.getIdentityRoute(inflatableKeyManager);

        assertThat(identityRoute)
                .containsKey("client")
                .containsValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"));

        KeyManagerUtils.removeIdentityRoute(inflatableKeyManager, "client");
        assertThat(KeyManagerUtils.getIdentityRoute(inflatableKeyManager)).isEmpty();
    }

    @Test
    void addClientIdentityRoutesWhenTryingToOverrideANonExistingRoute() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);
        KeyManagerUtils.overrideIdentityRoute(keyManager, "client","https://localhost:8443/", "https://localhost:8453/");
        Map<String, List<String>> clientIdentityRoute = KeyManagerUtils.getIdentityRoute(keyManager);

        assertThat(clientIdentityRoute)
                .containsKey("client")
                .containsValue(Arrays.asList("https://localhost:8443/", "https://localhost:8453/"));
    }

    @Test
    void createInflatableKeyManager() {
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createInflatableKeyManager();
        assertThat(keyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        assertThat(KeyManagerUtils.getAliases(keyManager)).containsExactly("dummy");
        assertThat(((InflatableX509ExtendedKeyManager) keyManager).getInnerKeyManager()).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) keyManager).getInnerKeyManager()).getInnerKeyManagers().get("dummy")).isInstanceOf(DummyX509ExtendedKeyManager.class);
    }

    @Test
    void createInflatableKeyManagerFromAnyInitialKeyManager() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager("my-key-manager", keyManager);
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("my-key-manager");
        assertThat(((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers().get("my-key-manager")).isEqualTo(keyManager);
    }

    @Test
    void addIdentityMaterialAsKeyManagerToInflatableKeyManager() {
        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager();
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("dummy");
        assertThat(((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers().get("dummy")).isInstanceOf(DummyX509ExtendedKeyManager.class);

        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-one", keyManagerOne);
        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-two", keyManagerTwo);
        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("key-manager-one", "key-manager-two");
        Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers.get("key-manager-one")).isEqualTo(keyManagerOne);
        assertThat(innerKeyManagers.get("key-manager-two")).isEqualTo(keyManagerTwo);
    }

    @Test
    void addIdentityMaterialAsKeyStoreToInflatableKeyManager() {
        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager();
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("dummy");
        assertThat(((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).isInstanceOf(AggregatedX509ExtendedKeyManager.class);
        assertThat(((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers().get("dummy")).isInstanceOf(DummyX509ExtendedKeyManager.class);

        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-one", identityOne, IDENTITY_PASSWORD);
        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-two", identityTwo, IDENTITY_PASSWORD);
        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("key-manager-one", "key-manager-two");
        Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers.get("key-manager-one")).isNotNull();
        assertThat(innerKeyManagers.get("key-manager-two")).isNotNull();
    }

    @Test
    void removeIdentityMaterialFromInflatableKeyManager() {
        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager();
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-one", identityOne, IDENTITY_PASSWORD);
        KeyManagerUtils.addIdentityMaterial(inflatableKeyManager, "key-manager-two", identityTwo, IDENTITY_PASSWORD);
        assertThat(KeyManagerUtils.getAliases(inflatableKeyManager)).containsExactly("key-manager-one", "key-manager-two");

        Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers.get("key-manager-one")).isNotNull();
        assertThat(innerKeyManagers.get("key-manager-two")).isNotNull();

        KeyManagerUtils.removeIdentityMaterial(inflatableKeyManager, "key-manager-one");

        innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) inflatableKeyManager).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers).doesNotContainKey("key-manager-one");
        assertThat(innerKeyManagers.get("key-manager-two")).isNotNull();
    }

    @Test
    void addIdentityMaterialAsKeyManagerToAWrappedInflatableKeyManagerInALoggingKeyManager() {
        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager();
        X509ExtendedKeyManager loggingKeyManager = KeyManagerUtils.createLoggingKeyManager(inflatableKeyManager);
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);
        assertThat(loggingKeyManager).isInstanceOf(LoggingX509ExtendedKeyManager.class);

        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        KeyManagerUtils.addIdentityMaterial(loggingKeyManager, "key-manager-one", keyManagerOne);
        KeyManagerUtils.addIdentityMaterial(loggingKeyManager, "key-manager-two", keyManagerTwo);
        assertThat(KeyManagerUtils.getAliases(loggingKeyManager)).containsExactly("key-manager-one", "key-manager-two");
        Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) ((DelegatingX509ExtendedKeyManager) loggingKeyManager).getInnerKeyManager()).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers.get("key-manager-one")).isEqualTo(keyManagerOne);
        assertThat(innerKeyManagers.get("key-manager-two")).isEqualTo(keyManagerTwo);
    }

    @Test
    void addIdentityMaterialAsKeyManagerToAWrappedInflatableKeyManagerInAggregatableKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);

        X509ExtendedKeyManager inflatableKeyManager = KeyManagerUtils.createInflatableKeyManager();
        assertThat(inflatableKeyManager).isInstanceOf(InflatableX509ExtendedKeyManager.class);

        X509ExtendedKeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, inflatableKeyManager);

        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        KeyManagerUtils.addIdentityMaterial(combinedKeyManager, "key-manager-two", keyManagerTwo);
        assertThat(KeyManagerUtils.getAliases(combinedKeyManager)).containsExactly("key-manager-two");
        Optional<X509ExtendedKeyManager> keyManagerOptional = ((AggregatedX509ExtendedKeyManager) combinedKeyManager).getInnerKeyManagers().values().stream()
                .filter(InflatableX509ExtendedKeyManager.class::isInstance)
                .findAny();

        assertThat(keyManagerOptional).isPresent();
        Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) ((InflatableX509ExtendedKeyManager) (keyManagerOptional.get())).getInnerKeyManager()).getInnerKeyManagers();
        assertThat(innerKeyManagers.get("key-manager-two")).isEqualTo(keyManagerTwo);
    }

    @Test
    void returnNoAliasesWhenItIsNotAnInflatableKeyManager() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        assertThat(KeyManagerUtils.getAliases(keyManager)).isEmpty();
    }

    @Test
    void returnAliasesForAggregatableKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);
        assertThat(KeyManagerUtils.getAliases(keyManager)).containsExactly("1", "2");
    }

    @Test
    void throwsExceptionWhenAddingIdentityMaterialToNonInflatableKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.addIdentityMaterial(keyManager, "key-manager-one", identityTwo, IDENTITY_PASSWORD))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("KeyManager should be an instance of: [nl.altindag.ssl.keymanager.InflatableX509ExtendedKeyManager], but received: [sun.security.ssl.SunX509KeyManagerImpl]");
    }

    @Test
    void throwsExceptionWhenAddingIdentityMaterialToNonInflatableKeyManagerWrappedInAggregatableKeyManager() {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);

        assertThatThrownBy(() -> KeyManagerUtils.addIdentityMaterial(keyManager, "key-manager-one", identityTwo, IDENTITY_PASSWORD))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("KeyManager should be an instance of: [nl.altindag.ssl.keymanager.InflatableX509ExtendedKeyManager], but received: [nl.altindag.ssl.keymanager.AggregatedX509ExtendedKeyManager]");
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

    @Test
    void throwExceptionWhenUnsupportedKeyManagerIsProvidedWhenAddingNewClientIdentityRoute() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.addIdentityRoute(keyManager, "another-server", "https://localhost:8443/"))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("KeyManager should be an instance of: [nl.altindag.ssl.keymanager.AggregatedX509ExtendedKeyManager], " +
                            "but received: [sun.security.ssl.SunX509KeyManagerImpl]");
    }

    @Test
    void throwExceptionWhenUnsupportedKeyManagerIsProvidedWhenGettingClientIdentityRoute() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.getIdentityRoute(keyManager))
                .isInstanceOf(GenericKeyManagerException.class)
                .hasMessage("KeyManager should be an instance of: [nl.altindag.ssl.keymanager.AggregatedX509ExtendedKeyManager], " +
                        "but received: [sun.security.ssl.SunX509KeyManagerImpl]");
    }

    @Test
    void keyStoreExceptionShouldBeWrappedInGenericKeyStoreException() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        PrivateKey privateKey = (PrivateKey) identity.getKey("dummy-client", "secret".toCharArray());
        Certificate[] chain = identity.getCertificateChain("dummy-client");

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class)) {
            KeyStore keyStore = mock(KeyStore.class);

            keyStoreUtilsMock.when(KeyStoreUtils::createKeyStore).thenReturn(keyStore);
            doThrow(new KeyStoreException("KABOOM"))
                    .when(keyStore).setKeyEntry(anyString(), any(PrivateKey.class), any(char[].class), any(Certificate[].class));

            assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(privateKey, chain))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("KABOOM");
        }
    }

}
