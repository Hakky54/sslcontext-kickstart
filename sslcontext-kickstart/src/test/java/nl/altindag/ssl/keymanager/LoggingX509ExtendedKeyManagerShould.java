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

import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.Principal;
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

}
