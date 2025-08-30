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
package nl.altindag.ssl.keymanager;

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.CertificateUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class LoggingX509ExtendedKeyManagerShould {

    private static LogCaptor logCaptor;
    private static Principal[] issuers;

    private X509ExtendedKeyManager innerMockedKeyManager;
    private X509ExtendedKeyManager victim;


    @BeforeAll
    static void setupIssuersAndLogCaptor() {
        List<Certificate> certificates = CertificateUtils.loadCertificate("pem/stackexchange.pem");
        assertThat(certificates).hasSize(1);

        Certificate certificate = certificates.get(0);
        assertThat(certificate).isInstanceOf(X509Certificate.class);

        X500Principal issuer = ((X509Certificate) certificate).getIssuerX500Principal();
        issuers = new Principal[]{issuer};
        logCaptor = LogCaptor.forClass(LoggingX509ExtendedKeyManager.class);
    }

    @AfterAll
    static void tearDown() {
        logCaptor.close();
    }

    @BeforeEach
    void setup() {
        innerMockedKeyManager = mock(X509ExtendedKeyManager.class);
        victim = new LoggingX509ExtendedKeyManager(innerMockedKeyManager);
    }

    @AfterEach
    void clearLogs() {
        logCaptor.clearLogs();
    }

    @Test
    void chooseClientAlias() {
        String[] keyTypes = new String[]{"RSA"};
        Socket socket = mock(Socket.class);

        when(innerMockedKeyManager.chooseClientAlias(keyTypes, issuers, socket)).thenReturn("some-alias");

        String alias = victim.chooseClientAlias(keyTypes, issuers, socket);
        assertThat(alias).isEqualTo("some-alias");

        verify(innerMockedKeyManager, times(1)).chooseClientAlias(keyTypes, issuers, socket);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a client alias for key types [RSA], while also using the Socket. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following client aliases [some-alias] for key types [RSA], while also using the Socket. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void chooseEngineClientAlias() {
        String[] keyTypes = new String[]{"RSA"};
        SSLEngine sslEngine = mock(SSLEngine.class);

        when(innerMockedKeyManager.chooseEngineClientAlias(keyTypes, issuers, sslEngine)).thenReturn("some-alias");

        String alias = victim.chooseEngineClientAlias(keyTypes, issuers, sslEngine);
        assertThat(alias).isEqualTo("some-alias");

        verify(innerMockedKeyManager, times(1)).chooseEngineClientAlias(keyTypes, issuers, sslEngine);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a client alias for key types [RSA], while also using the SSLEngine. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following client aliases [some-alias] for key types [RSA], while also using the SSLEngine. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void chooseServerAlias() {
        String keyType = "RSA";
        Socket socket = mock(Socket.class);

        when(innerMockedKeyManager.chooseServerAlias(keyType, issuers, socket)).thenReturn("some-alias");

        String alias = victim.chooseServerAlias(keyType, issuers, socket);
        assertThat(alias).isEqualTo("some-alias");

        verify(innerMockedKeyManager, times(1)).chooseServerAlias(keyType, issuers, socket);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a server alias for key types [RSA], while also using the Socket. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following server aliases [some-alias] for key types [RSA], while also using the Socket. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void chooseEngineServerAlias() {
        String keyType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        when(innerMockedKeyManager.chooseEngineServerAlias(keyType, issuers, sslEngine)).thenReturn("some-alias");

        String alias = victim.chooseEngineServerAlias(keyType, issuers, sslEngine);
        assertThat(alias).isEqualTo("some-alias");

        verify(innerMockedKeyManager, times(1)).chooseEngineServerAlias(keyType, issuers, sslEngine);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a server alias for key types [RSA], while also using the SSLEngine. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following server aliases [some-alias] for key types [RSA], while also using the SSLEngine. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void attemptToGetPrivateKey() {
        String alias = "some-alias";

        when(innerMockedKeyManager.getPrivateKey(alias)).thenReturn(null);

        PrivateKey privateKey = victim.getPrivateKey(alias);

        assertThat(privateKey).isNull();
        verify(innerMockedKeyManager, times(1)).getPrivateKey(alias);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).contains("Attempting to get the private key for the alias: some-alias");
    }

    @Test
    void getPrivateKey() {
        PrivateKey mockedPrivateKey = mock(PrivateKey.class);
        String alias = "some-alias";

        when(innerMockedKeyManager.getPrivateKey(alias)).thenReturn(mockedPrivateKey);

        PrivateKey privateKey = victim.getPrivateKey(alias);

        assertThat(privateKey)
                .isNotNull()
                .isEqualTo(mockedPrivateKey);

        verify(innerMockedKeyManager, times(1)).getPrivateKey(alias);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to get the private key for the alias: some-alias")
                .contains("Found a private key for the alias: some-alias");
    }

    @Test
    void attemptToGetCertificateChain() {
        String alias = "some-alias";

        when(innerMockedKeyManager.getCertificateChain(alias)).thenReturn(null);

        X509Certificate[] certificateChain = victim.getCertificateChain(alias);

        assertThat(certificateChain).isNull();

        verify(innerMockedKeyManager, times(1)).getCertificateChain(alias);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).contains("Attempting to get the certificate chain for the alias: some-alias");
    }

    @Test
    void attemptToGetCertificateChainReturnsEmpty() {
        String alias = "some-alias";

        when(innerMockedKeyManager.getCertificateChain(alias)).thenReturn(new X509Certificate[]{});

        X509Certificate[] certificateChain = victim.getCertificateChain(alias);

        assertThat(certificateChain).isEmpty();

        verify(innerMockedKeyManager, times(1)).getCertificateChain(alias);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).contains("Attempting to get the certificate chain for the alias: some-alias");
    }

    @Test
    void getCertificateChain() {
        X509Certificate mockedCertificate = mock(X509Certificate.class);
        String alias = "some-alias";

        when(innerMockedKeyManager.getCertificateChain(alias)).thenReturn(new X509Certificate[]{mockedCertificate});
        when(mockedCertificate.toString()).thenReturn("CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US");

        X509Certificate[] certificateChain = victim.getCertificateChain(alias);

        assertThat(certificateChain)
                .isNotNull()
                .contains(mockedCertificate);

        verify(innerMockedKeyManager, times(1)).getCertificateChain(alias);
        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).containsExactly("Attempting to get the certificate chain for the alias: some-alias",
                "Found the certificate chain with a size of 1 for the alias: some-alias. See below for the full chain:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void getClientAliases() {
        String keyType = "RSA";

        when(innerMockedKeyManager.getClientAliases(keyType, issuers)).thenReturn(new String[]{"some-alias"});

        String[] alias = victim.getClientAliases(keyType, issuers);
        assertThat(alias).contains("some-alias");

        verify(innerMockedKeyManager, times(1)).getClientAliases(keyType, issuers);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a client alias for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following client aliases [some-alias] for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void getServerAliases() {
        String keyType = "RSA";

        when(innerMockedKeyManager.getServerAliases(keyType, issuers)).thenReturn(new String[]{"some-alias"});

        String[] alias = victim.getServerAliases(keyType, issuers);
        assertThat(alias).contains("some-alias");

        verify(innerMockedKeyManager, times(1)).getServerAliases(keyType, issuers);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a server alias for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .contains("Found the following server aliases [some-alias] for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void notLogFoundAlisWhenGettingServerAliasesIfItIsReturningANull() {
        String keyType = "RSA";

        when(innerMockedKeyManager.getServerAliases(keyType, issuers)).thenReturn(null);

        String[] alias = victim.getServerAliases(keyType, issuers);
        assertThat(alias).isNull();

        verify(innerMockedKeyManager, times(1)).getServerAliases(keyType, issuers);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .containsExactly("Attempting to find a server alias for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]")
                .doesNotContain("Found the following server aliases [some-alias] for key types [RSA]. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

    @Test
    void notLogIssuersIfAbsentForGetServerAliases() {
        String keyType = "RSA";

        when(innerMockedKeyManager.getServerAliases(keyType, null)).thenReturn(new String[]{"some-alias"});

        String[] alias = victim.getServerAliases(keyType, null);
        assertThat(alias).contains("some-alias");

        verify(innerMockedKeyManager, times(1)).getServerAliases(keyType, null);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a server alias for key types [RSA].")
                .contains("Found the following server aliases [some-alias] for key types [RSA].");
    }

    @Test
    void notLogIssuersIfEmptyForGetServerAliases() {
        String keyType = "RSA";
        Principal[] issuers = {};

        when(innerMockedKeyManager.getServerAliases(keyType, issuers)).thenReturn(new String[]{"some-alias"});

        String[] alias = victim.getServerAliases(keyType, issuers);
        assertThat(alias).contains("some-alias");

        verify(innerMockedKeyManager, times(1)).getServerAliases(keyType, issuers);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .contains("Attempting to find a server alias for key types [RSA].")
                .contains("Found the following server aliases [some-alias] for key types [RSA].");
    }

    @Test
    void notLogAliasIfAbsentGetServerAliases() {
        String keyType = "RSA";

        when(innerMockedKeyManager.getServerAliases(keyType, null)).thenReturn(new String[]{});

        String[] alias = victim.getServerAliases(keyType, null);
        assertThat(alias).isEmpty();

        verify(innerMockedKeyManager, times(1)).getServerAliases(keyType, null);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).containsExactly("Attempting to find a server alias for key types [RSA].");
    }

    @Test
    void notLogAliasWhenChooseClientAliasReturnsNoAlias() {
        String[] keyTypes = new String[]{"RSA"};
        Socket socket = mock(Socket.class);

        when(innerMockedKeyManager.chooseClientAlias(keyTypes, issuers, socket)).thenReturn(null);

        String alias = victim.chooseClientAlias(keyTypes, issuers, socket);
        assertThat(alias).isNull();

        verify(innerMockedKeyManager, times(1)).chooseClientAlias(keyTypes, issuers, socket);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs)
                .containsExactly("Attempting to find a client alias for key types [RSA], while also using the Socket. See below for list of the issuers:" + System.lineSeparator() +
                        "[CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US]");
    }

}
