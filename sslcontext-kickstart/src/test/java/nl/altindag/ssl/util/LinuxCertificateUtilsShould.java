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
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    void getCertificatesWhenFileExistAndIsARegularFile() {
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

    @Test
    void getCertificatesWhenFilesExistUnderADirectory() {
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

    @Test
    void getCertificatesReturnsEmptyListWhenFileDoesNotExist() {
        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            if ("exists".equals(method.getName())) {
                return false;
            } else if ("isRegularFile".equals(method.getName())) {
                return true;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getCertificatesReturnsEmptyListWhenFileExistButIsNotARegularFile() {
        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            String methodName = method.getName();
            if ("exists".equals(methodName)) {
                return true;
            } else if ("isRegularFile".equals(methodName)) {
                return false;
            } else if ("isDirectory".equals(methodName)) {
                return true;
            } else if ("walk".equals(methodName)) {
                return Stream.of(Paths.get("/etc/ssl/certs/some-certificate.pem"));
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getCertificatesReturnsCertificatesWhenFileExistWithinDirectory() {
        if (!OPERATING_SYSTEM.contains("windows")) {
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
                     String methodName = method.getName();

                     if (invocation.getArguments().length == 0) {
                         return invocation.callRealMethod();
                     }

                     String path = invocation.getArguments()[0].toString();
                     if ("exists".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return true;
                     } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return false;
                     } else if ("isDirectory".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return true;
                     } else if ("walk".equals(methodName)) {
                         return Stream.of(Paths.get("/etc/ssl/certs/some-certificate.pem"));
                     } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs/some-certificate.pem".equals(path)) {
                         return true;
                     } else if ("exists".equals(methodName)) {
                         return false;
                     } else {
                         return invocation.callRealMethod();
                     }
                 })) {

                List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
                assertThat(certificates).isNotEmpty();
            }
        }
    }

    @Test
    void wrapAnIOExceptionInAGenericIOExceptionWhenFilesWalkFails() {
        if (!OPERATING_SYSTEM.contains("windows")) {
            try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                Method method = invocation.getMethod();
                String methodName = method.getName();

                if (invocation.getArguments().length == 0) {
                    return invocation.callRealMethod();
                }

                String path = invocation.getArguments()[0].toString();
                if ("exists".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return true;
                } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return false;
                } else if ("isDirectory".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return true;
                } else if ("walk".equals(methodName)) {
                    throw new IOException("KABOOM");
                } else {
                    return invocation.callRealMethod();
                }
            })) {

                assertThatThrownBy(LinuxCertificateUtils::getCertificates)
                        .isInstanceOf(GenericIOException.class)
                        .hasMessageContaining("KABOOM");
            }
        }
    }

    @Test
    void notGetCertificatesIfPathIsNotARegularFileAndAlsoNotADirectory() {
        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            String methodName = method.getName();

            if ("exists".equals(methodName)) {
                return false;
            } else if ("isRegularFile".equals(methodName)) {
                return false;
            } else if ("isDirectory".equals(methodName)) {
                return true;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void containAListOfToBeSearchPathsForCertificates() {
        if (!OPERATING_SYSTEM.contains("windows")) {
            List<String> capturedPaths = new ArrayList<>();
            try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                Method method = invocation.getMethod();
                if ("exists".equals(method.getName())) {
                    String absolutePath = invocation.getArguments()[0].toString();
                    capturedPaths.add(absolutePath);
                    return false;
                } else {
                    return invocation.callRealMethod();
                }
            })) {

                LinuxCertificateUtils.getCertificates();
                assertThat(capturedPaths).containsExactly(
                        "/etc/ssl/certs",
                        "/etc/pki/nssdb",
                        "/usr/local/share/ca-certificates",
                        "/usr/share/ca-certificates",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                        "/etc/pki/ca-trust/source/anchors",
                        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                        System.getProperty("user.home") + "/.pki/nssdb"
                );
            }
        }
    }

}
