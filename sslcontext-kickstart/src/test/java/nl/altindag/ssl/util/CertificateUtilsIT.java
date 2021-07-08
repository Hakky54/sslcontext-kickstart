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

import com.sun.net.httpserver.HttpsServer;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.ServerUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class CertificateUtilsIT {

    @Test
    void getRemoteCertificates() {
        Map<String, List<Certificate>> certificatesFromRemote = CertificateUtils.getCertificate(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote).containsKeys(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote.get("https://stackoverflow.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://github.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://www.linkedin.com/")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesAsPem() {
        Map<String, List<String>> certificatesFromRemote = CertificateUtils.getCertificateAsPem(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote).containsKeys(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote.get("https://stackoverflow.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://github.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://www.linkedin.com/")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteSelfSignedCertificate() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer server = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "");
        server.start();

        Map<String, List<Certificate>> certificatesFromRemote = CertificateUtils.getCertificate("https://localhost:8443");

        server.stop(0);
        executorService.shutdownNow();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:8443");
        assertThat(certificatesFromRemote.get("https://localhost:8443")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCustomRootCaSignedCertificate() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-three/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-three/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer server = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "");
        server.start();

        Map<String, List<Certificate>> certificatesFromRemote = CertificateUtils.getCertificate("https://localhost:8443");

        server.stop(0);
        executorService.shutdownNow();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:8443");
        assertThat(certificatesFromRemote.get("https://localhost:8443")).hasSizeGreaterThan(0);
    }

}
