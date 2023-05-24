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

import io.javalin.Javalin;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.ServerUtils;
import nl.altindag.ssl.exception.GenericCertificateException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class CertificateUtilsIT {

    @Test
    void getRemoteCertificates() {
        Supplier<Map<String, List<X509Certificate>>> certificateSupplier = () -> CertificateUtils.getCertificate(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        int amountOfRetries = 0;
        int maxAmountOfRetries = 10;

        Map<String, List<X509Certificate>> certificatesFromRemote = null;

        while (certificatesFromRemote == null && amountOfRetries < maxAmountOfRetries) {
            try {
                certificatesFromRemote = certificateSupplier.get();
                amountOfRetries++;
            } catch (GenericCertificateException ignored) {}
        }

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys(
                        "https://stackoverflow.com/",
                        "https://github.com/",
                        "https://www.linkedin.com/"
                );

        assertThat(certificatesFromRemote.get("https://stackoverflow.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://github.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://www.linkedin.com/")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesFromList() {
        List<String> urls = Arrays.asList(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        Supplier<Map<String, List<X509Certificate>>> certificateSupplier = () -> CertificateUtils.getCertificate(urls);

        int amountOfRetries = 0;
        int maxAmountOfRetries = 10;

        Map<String, List<X509Certificate>> certificatesFromRemote = null;

        while (certificatesFromRemote == null && amountOfRetries < maxAmountOfRetries) {
            try {
                certificatesFromRemote = certificateSupplier.get();
                amountOfRetries++;
            } catch (GenericCertificateException ignored) {}
        }

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys(
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
    void getRemoteCertificatesAsPemFromList() {
        List<String> urls = Arrays.asList(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        Map<String, List<String>> certificatesFromRemote = CertificateUtils.getCertificateAsPem(urls);

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
    void getRemoteSelfSignedCertificate() {
        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Javalin server = ServerUtils.createServer(sslFactoryForServerOne);
        server.start();

        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificate("https://localhost:8443");

        server.stop();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:8443");
        assertThat(certificatesFromRemote.get("https://localhost:8443")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCustomRootCaSignedCertificate() {
        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-three/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-three/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Javalin server = ServerUtils.createServer(sslFactoryForServerOne);
        server.start();

        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificate("https://localhost:8443");

        server.stop();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:8443");
        assertThat(certificatesFromRemote.get("https://localhost:8443")).hasSizeGreaterThan(0);
    }

}
