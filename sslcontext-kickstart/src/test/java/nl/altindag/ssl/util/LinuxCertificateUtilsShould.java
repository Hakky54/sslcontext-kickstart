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


import nl.altindag.ssl.IOTestUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

/**
 * @author Hakan Altindag
 */
class LinuxCertificateUtilsShould {

    private static final String OPERATING_SYSTEM = System.getProperty("os.name").toLowerCase();

    @Test
    void getCertificate() {
        if (OPERATING_SYSTEM.contains("linux")) {
            List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
            assertThat(certificates).isNotEmpty();
        }
    }

    @Test
    void loadCertificateIgnoresInvalidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "invalid.pem");
        List<Certificate> certificates = LinuxCertificateUtils.loadCertificate(path);
        assertThat(certificates).isEmpty();
        Files.delete(path);
    }

    @Test
    void loadCertificateReadsValidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "badssl-certificate.pem");
        List<Certificate> certificates = LinuxCertificateUtils.loadCertificate(path);
        assertThat(certificates).isNotEmpty();
        Files.delete(path);
    }

    @Test
    void getCertificatesWhenFileExistAndIsARegularFile() throws IOException {
        InputStream inputStream = IOUtils.getResourceAsStream("pem/badssl-certificate.pem");
        String content = IOUtils.getContent(inputStream);
        List<Certificate> mockedCertificates = CertificateUtils.parsePemCertificate(content);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadCertificate".equals(method.getName())) {
                return mockedCertificates;
            } else {
                return invocation.callRealMethod();
            }
        });
             MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("exists".equals(method.getName())) {
                     return true;
                 } else if ("isRegularFile".equals(method.getName())) {
                     return true;
                 } else {
                     return invocation.callRealMethod();
                 }
             })) {

            List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
            assertThat(certificates).isNotEmpty();
        }

    }

}
