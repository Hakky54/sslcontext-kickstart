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

package nl.altindag.ssl.keymanager;

import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class CompositeX509ExtendedKeyManagerShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void returnPrivateKeyForAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        assertThat(keyManager).isNotNull();

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(keyManager.getPrivateKey("dummy-client")).isNotNull();
        assertThat(keyManager.getPrivateKey("another-server")).isNotNull();
    }

    @Test
    void returnNullForUnknownAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getPrivateKey("TOGG")).isNull();
    }

    @Test
    void returnCertificateChain() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);

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
    void returnNullForUnknownAliasWhenGettingCertificateChain() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);

        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(keyManager.getCertificateChain("TOGG")).isNull();
    }

    @Test
    void returnNullWhenCertificateChainLengthIsZeroWhenGettingCertificateChain() {
        X509ExtendedKeyManager mockedInnerKeyManager = mock(X509ExtendedKeyManager.class);
        when(mockedInnerKeyManager.getCertificateChain(anyString())).thenReturn(new X509Certificate[] {});

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(Collections.singletonList(mockedInnerKeyManager));
        X509Certificate[] certificateChain = keyManager.getCertificateChain("dummy-client");

        assertThat(certificateChain).isNull();
    }


    @Test
    void getServerAliases() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String[] aliases = keyManager.getServerAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    void getServerAliasesReturnsNullWhenThereIsNoMatchingIssuer() {
        X509ExtendedKeyManager mockedInnerKeyManager = mock(X509ExtendedKeyManager.class);
        Principal mockedIssuer = mock(Principal.class);
        Principal[] mockedIssuers = new Principal[]{ mockedIssuer };
        when(mockedInnerKeyManager.getServerAliases("RSA", mockedIssuers)).thenReturn(null);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(Collections.singletonList(mockedInnerKeyManager));
        String[] serverAliases = keyManager.getServerAliases("RSA", mockedIssuers);

        assertThat(serverAliases).isNull();
    }

    @Test
    void getClientAliases() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String[] aliases = keyManager.getClientAliases("RSA", null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(aliases).containsExactlyInAnyOrder("dummy-client", "another-server");
    }

    @Test
    void chooseFirstServerAliasWithMatchingKeyType() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstEngineServerAliasWithMatchingKeyType() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseEngineServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstServerAliasWithMatchingKeyTypeWithDifferentOrderOfInitializationOfTheKeyManager() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerTwo, keyManagerOne)
        );

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void chooseFirstEngineServerAliasWithMatchingKeyTypeWithDifferentOrderOfInitializationOfTheKeyManager() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerTwo, keyManagerOne)
        );

        String alias = keyManager.chooseServerAlias("RSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingServerAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseServerAlias("ECDSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingEngineServerAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseEngineServerAlias("ECDSA", null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void chooseFirstClientAliasWithMatchingKeyType() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstClientAliasWithMatchingKeyTypeWithPreferredAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo),
                Collections.singletonMap("another-server", Collections.singletonList(URI.create("https://localhost:8443/"))),
                Collections.emptyMap()
        );

        Socket socket = mock(Socket.class);
        InetSocketAddress socketAddress = mock(InetSocketAddress.class);

        when(socket.getRemoteSocketAddress()).thenReturn(socketAddress);
        when(socketAddress.getPort()).thenReturn(8443);
        when(socketAddress.getHostName()).thenReturn("localhost");

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, socket);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void chooseFirstClientAliasWithMatchingKeyTypWhilePreferredAliasIsIgnoredBecauseRemoteSocketAddressIsNotAnInstanceOfInetSocketAddress() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo),
                Collections.singletonMap("another-server", Collections.singletonList(URI.create("https://localhost:8443/"))),
                Collections.emptyMap()
        );

        Socket socket = mock(Socket.class);
        SocketAddress socketAddress = mock(SocketAddress.class);
        when(socket.getRemoteSocketAddress()).thenReturn(socketAddress);

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, socket);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstClientAliasWithMatchingKeyTypeWhilePreferredAliasIsIgnoredBecauseSocketIsNull() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo),
                Collections.singletonMap("another-server", Collections.singletonList(URI.create("https://localhost:8443/"))),
                Collections.emptyMap()
        );

        String alias = keyManager.chooseClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstEngineClientAliasWithMatchingKeyType() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseEngineClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void chooseFirstEngineClientAliasWithMatchingKeyTypeWithPreferredAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo),
                Collections.singletonMap("another-server", Collections.singletonList(URI.create("https://localhost:8443/"))),
                Collections.emptyMap()
        );

        SSLEngine sslEngine = mock(SSLEngine.class);
        when(sslEngine.getPeerPort()).thenReturn(8443);
        when(sslEngine.getPeerHost()).thenReturn("localhost");

        String alias = keyManager.chooseEngineClientAlias(new String[]{"RSA"}, null, sslEngine);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("another-server");
    }

    @Test
    void chooseFirstEngineClientAliasWithMatchingKeyTypeWhilePreferredAliasIsIgnoredBecauseSslEngineIsNull() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo),
                Collections.singletonMap("another-server", Collections.singletonList(URI.create("https://localhost:8443/"))),
                Collections.emptyMap()
        );

        String alias = keyManager.chooseEngineClientAlias(new String[]{"RSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isEqualTo("dummy-client");
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingClientAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseClientAlias(new String[]{"ECDSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

    @Test
    void returnNullWhenThereIsNoMatchOfKeyTypeForKeyManagersWhileChoosingEngineClientAlias() throws KeyStoreException {
        KeyStore identityOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509ExtendedKeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        CompositeX509ExtendedKeyManager keyManager = new CompositeX509ExtendedKeyManager(
                Arrays.asList(keyManagerOne, keyManagerTwo)
        );

        String alias = keyManager.chooseEngineClientAlias(new String[]{"ECDSA"}, null, null);

        assertThat(keyManager).isNotNull();
        assertThat(keyManager.size()).isEqualTo(2);
        assertThat(identityOne.size()).isEqualTo(1);
        assertThat(identityTwo.size()).isEqualTo(1);
        assertThat(alias).isNull();
    }

}
