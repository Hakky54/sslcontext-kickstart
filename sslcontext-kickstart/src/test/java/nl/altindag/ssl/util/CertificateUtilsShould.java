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

import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class CertificateUtilsShould {

    private static final String PEM_LOCATION = "pem/";
    private static final String DER_LOCATION = "der/";
    private static final String P7B_LOCATION = "p7b/";
    private static final String TEMPORALLY_PEM_LOCATION = System.getProperty("user.home");

    @Test
    void generateAliasForX509Certificate() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));
        X509Certificate certificate = trustManager.getAcceptedIssuers()[0];

        String alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isEqualTo("CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US");
    }

    @Test
    void generateAliasForCertificate() {
        Certificate certificate = mock(Certificate.class);

        String alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isNotBlank();
    }

    @Test
    void loadCertificateFromClassPath() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "badssl-certificate.pem");
        assertThat(certificates).hasSize(1);
    }

    @Test
    void loadDerCertificateFromClassPath() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(DER_LOCATION + "digicert.cer");
        assertThat(certificates).hasSize(1);
    }

    @Test
    void loadP7bSingleCertificateFromClassPath() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(P7B_LOCATION + "digicert.p7b");
        assertThat(certificates).hasSize(1);
    }

    @Test
    void loadP7bCertificateChainFromClassPath() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(P7B_LOCATION + "siggycentral-chain.p7b");
        assertThat(certificates).hasSize(3);
    }

    @Test
    void loadMultipleCertificatesFromDifferentFiles() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(
                PEM_LOCATION + "badssl-certificate.pem",
                PEM_LOCATION + "github-certificate.pem",
                PEM_LOCATION + "stackexchange.pem"
        );
        assertThat(certificates).hasSize(3);
    }

    @Test
    void loadCertificateFromDirectory() throws IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");
        List<Certificate> certificates = CertificateUtils.loadCertificate(certificatePath);

        assertThat(certificates).hasSize(1);

        Files.delete(certificatePath);
    }

    @Test
    void throwExceptionWhenLoadingCertificateFromUnknownPath() {
        Path certificatePath = Paths.get("somewhere-in-space.pem");
        assertThatThrownBy(() -> CertificateUtils.loadCertificate(certificatePath))
                .isInstanceOf(GenericIOException.class)
                .hasMessageContaining("java.nio.file.NoSuchFileException: somewhere-in-space.pem");
    }

    @Test
    void loadCertificateFromInputStream() throws IOException {
        List<Certificate> certificates;
        try(InputStream inputStream = getResource(PEM_LOCATION + "multiple-certificates.pem")) {
            certificates = CertificateUtils.loadCertificate(inputStream);
        }

        assertThat(certificates).hasSize(3);
    }

    @Test
    void getSystemTrustedCertificates() {
        String operatingSystem = System.getProperty("os.name").toLowerCase();
        List<X509Certificate> certificates = CertificateUtils.getSystemTrustedCertificates();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows")) {
            assertThat(certificates).isNotEmpty();
        }

        if (operatingSystem.contains("linux")) {
            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getSystemTrustedCertificatesDoesNotReturnCertificateIfNotACertificateEntry() throws KeyStoreException {
        KeyStore keyStore = mock(KeyStore.class);
        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class, InvocationOnMock::getMock)) {

            keyStoreUtilsMockedStatic.when(KeyStoreUtils::loadSystemKeyStores).thenReturn(Collections.singletonList(keyStore));
            when(keyStore.aliases()).thenReturn(Collections.enumeration(Collections.singletonList("client")));
            when(keyStore.isCertificateEntry("client")).thenReturn(false);

            List<X509Certificate> certificates = CertificateUtils.getSystemTrustedCertificates();

            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getCertificatesReturnsEmptyWhenNonHttpsUrlIsProvided() {
        Map<String, List<Certificate>> certificates = CertificateUtils.getCertificate("http://www.google.com/");

        assertThat(certificates).containsKey("http://www.google.com/");
        assertThat(certificates.get("http://www.google.com/")).isEmpty();
    }

    @Test
    void notAddSubjectAndIssuerAsHeaderWhenCertificateTypeIsNotX509Certificate() throws CertificateEncodingException {
        Certificate certificate = mock(Certificate.class);

        when(certificate.getEncoded()).thenReturn(CertificateUtils.loadCertificate(PEM_LOCATION + "stackexchange.pem").get(0).getEncoded());

        String pem = CertificateUtils.convertToPem(certificate);
        assertThat(pem)
                .doesNotContain("subject", "issuer")
                .contains("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
    }

    @Test
    void getJdkTrustedCertificates() {
        List<X509Certificate> jdkTrustedCertificates = CertificateUtils.getJdkTrustedCertificates();

        assertThat(jdkTrustedCertificates).hasSizeGreaterThan(0);
    }

    @Test
    void getRootCaIfPossibleReturnsJdkTrustedCaCertificateWhenNoAuthorityInfoAccessExtensionIsPresent() {
        List<Certificate> certificates = CertificateUtils.getCertificate("https://www.reddit.com/")
                .get("https://www.reddit.com/");

        try (MockedStatic<CertificateUtils> certificateUtilsMockedStatic = mockStatic(CertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName())) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            certificateUtilsMockedStatic.when(() -> CertificateUtils.getRootCaFromAuthorityInfoAccessExtensionIfPresent(any(X509Certificate.class)))
                    .thenReturn(Collections.emptyList());

            X509Certificate certificate = (X509Certificate) certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = CertificateUtils.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isNotEmpty();

            certificateUtilsMockedStatic.verify(() -> CertificateUtils.getRootCaFromJdkTrustedCertificates(certificate), times(1));
        }
    }

    @Test
    void getRootCaIfPossibleReturnsEmptyListWhenNoAuthorityInfoAccessExtensionIsPresentAndNoMatching() {
        List<Certificate> certificates = CertificateUtils.getCertificate("https://www.reddit.com/")
                .get("https://www.reddit.com/");

        try (MockedStatic<CertificateUtils> certificateUtilsMockedStatic = mockStatic(CertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName()) || "getRootCaFromJdkTrustedCertificates".equals(method.getName())) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            certificateUtilsMockedStatic.when(() -> CertificateUtils.getRootCaFromAuthorityInfoAccessExtensionIfPresent(any(X509Certificate.class)))
                    .thenReturn(Collections.emptyList());

            certificateUtilsMockedStatic.when(() -> CertificateUtils.getRootCaFromJdkTrustedCertificates(any(X509Certificate.class)))
                    .thenReturn(Collections.emptyList());

            X509Certificate certificate = (X509Certificate) certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = CertificateUtils.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isEmpty();

            certificateUtilsMockedStatic.verify(() -> CertificateUtils.getRootCaFromAuthorityInfoAccessExtensionIfPresent(certificate), times(1));
            certificateUtilsMockedStatic.verify(() -> CertificateUtils.getRootCaFromJdkTrustedCertificates(certificate), times(1));
        }
    }

    @Test
    void getRootCaFromChainIfPossibleReturnsEmptyListWhenNoCertificatesHaveBeenProvided() {
        List<X509Certificate> rootCa = CertificateUtils.getRootCaFromChainIfPossible(new Certificate[]{});
        assertThat(rootCa).isEmpty();
    }

    @Test
    void getRootCaFromChainIfPossibleReturnsEmptyListWhenProvidedCertificateIsNotAnInstanceOfX509Certificate() {
        List<X509Certificate> rootCa = CertificateUtils.getRootCaFromChainIfPossible(new Certificate[]{mock(Certificate.class)});
        assertThat(rootCa).isEmpty();
    }

    @Test
    void getRootCaFromAuthorityInfoAccessExtensionIfPresentReturnsEmptyListWhenCertificateIsNotInstanceOfX509CertImpl() {
        List<X509Certificate> rootCa = CertificateUtils.getRootCaFromAuthorityInfoAccessExtensionIfPresent(mock(X509Certificate.class));
        assertThat(rootCa).isEmpty();
    }

    @Test
    void ThrowsGenericCertificateExceptionWhenGetCertificatesFromRemoteFileFails() {
        try (MockedStatic<CertificateFactory> certificateFactoryMockedStatic = mockStatic(CertificateFactory.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName())) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {

            certificateFactoryMockedStatic.when(() -> CertificateFactory.getInstance("X.509"))
                    .thenThrow(CertificateException.class);

            URI uri = URI.create("https://www.reddit.com/");
            assertThatThrownBy(() -> CertificateUtils.getCertificatesFromRemoteFile(uri, null))
                    .isInstanceOf(GenericCertificateException.class);
        }
    }

    @Test
    void throwsGenericCertificateExceptionWhenGettingCertificateEncodingException() throws CertificateEncodingException {
        Certificate certificate = mock(Certificate.class);

        doThrow(new CertificateEncodingException("KABOOM!")).when(certificate).getEncoded();

        assertThatThrownBy(() -> CertificateUtils.convertToPem(certificate))
                .isInstanceOf(GenericCertificateException.class)
                .hasMessage("java.security.cert.CertificateEncodingException: KABOOM!");
    }

    @Test
    void throwsUncheckedIOExceptionWhenUrlIsUnreachable() {
        assertThatThrownBy(() -> CertificateUtils.getCertificate("https://localhost:1234/"))
                .isInstanceOf(GenericIOException.class);
    }

    @Test
    void throwsGenericIOExceptionWhenCloseOfTheStreamFails() throws IOException {
        InputStream inputStream = spy(getResource(PEM_LOCATION + "multiple-certificates.pem"));

        doThrow(new IOException("Could not read the content")).when(inputStream).close();

        assertThatThrownBy(() -> CertificateUtils.loadCertificate(inputStream))
                .isInstanceOf(GenericIOException.class)
                .hasRootCauseMessage("Could not read the content");
    }

    private Path copyFileToHomeDirectory(String path, String fileName) throws IOException {
        try (InputStream file = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TEMPORALLY_PEM_LOCATION, fileName);
            Files.copy(Objects.requireNonNull(file), destination, REPLACE_EXISTING);
            return destination;
        }
    }

    private InputStream getResource(String path) {
        return this.getClass().getClassLoader().getResourceAsStream(path);
    }

}
