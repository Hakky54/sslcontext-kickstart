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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.server.service.Server;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class CertificateExtractingClientIT {

    private SSLFactory sslFactoryForServer;

    @BeforeEach
    void setupServer() {
        sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .build();
    }

    @Test
    void shouldTimeoutIfServerFailsToRespondInTimeAndReturnsEmptyListOfCertificates() {
        try (LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class);) {
            CertificateExtractingClient client = CertificateExtractingClient.builder()
                    .withResolvedRootCa(true)
                    .withTimeout(100)
                    .build();

            Server server = Server.builder(sslFactoryForServer)
                    .withPort(1234)
                    .withDelayedResponseTime(200)
                    .build();

            List<X509Certificate> certificates = client.get("https://localhost:1234");
            assertThat(certificates).isEmpty();
            assertThat(logCaptor.getDebugLogs()).contains("The client didn't get a respond within the configured time-out of [100] milliseconds from: [https://localhost:1234]");

            server.stop();
        }
    }

    @Test
    void shouldNotTimeoutIfServerRespondsInTime() {
        try (LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class);) {
            CertificateExtractingClient client = CertificateExtractingClient.builder()
                    .withResolvedRootCa(true)
                    .withTimeout(400)
                    .build();

            Server server = Server.builder(sslFactoryForServer)
                    .withPort(5678)
                    .withDelayedResponseTime(200)
                    .build();

            List<X509Certificate> certificates = client.get("https://localhost:5678");
            assertThat(certificates).isNotEmpty();
            assertThat(logCaptor.getDebugLogs()).isEmpty();

            server.stop();
        }
    }

    @Test
    void shouldNotFailWhenResolvingRootCaWhichContainsAnInvalidAuthorityInfoAccess() {
        try(LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class)) {
            CertificateExtractingClient client = CertificateExtractingClient.builder()
                    .withResolvedRootCa(true)
                    .build();

            SSLFactory sslFactory = SSLFactory.builder()
                    .withIdentityMaterial("keystore/identity-with-invalid-authority-info-access.jks", "secret".toCharArray())
                    .withTrustMaterial("keystore/truststore.jks", "secret".toCharArray())
                    .build();

            Server server = Server.builder(sslFactory)
                    .withPort(9999)
                    .build();

            List<X509Certificate> certificates = client.get("https://localhost:9999");
            assertThat(certificates).isNotEmpty();
            assertThat(logCaptor.getDebugLogs()).contains("Skipped getting certificate from remote file while using the following location [http://google.com/DigiCertTLSRSASHA2562020CA1-1.crt]");

            server.stop();
        }
    }

}
