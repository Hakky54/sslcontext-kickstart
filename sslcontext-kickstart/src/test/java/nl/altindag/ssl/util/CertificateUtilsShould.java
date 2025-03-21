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

import nl.altindag.ssl.TestConstants;
import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static nl.altindag.ssl.TestConstants.DER_LOCATION;
import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.ssl.TestConstants.P7B_LOCATION;
import static nl.altindag.ssl.TestConstants.PEM_LOCATION;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class CertificateUtilsShould {

    @Test
    void generateAliasForX509Certificate() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));
        X509Certificate certificate = trustManager.getAcceptedIssuers()[0];

        String alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isEqualTo("cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us".toLowerCase(Locale.ENGLISH));
    }

    @Test
    void generateAliasForX509CertificateWithReplacingInvalidCharacters() {
        X509Certificate certificate = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);

        when(certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName(X500Principal.CANONICAL))
                .thenReturn("cn=*.youtube.google.com_o=google\\ llc,l=*mountain *view\\ top,st=california,c=us")
                .thenReturn("cn=go daddy secure certificate authority - g2,ou=http://certs.godaddy.com/repository/,o=godaddy.com\\, inc.,l=scottsdale,st=arizona,c=us");

        String alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isEqualTo("cn=youtubegooglecom_o=google-llc_l=mountain-view-top_st=california_c=us".toLowerCase(Locale.ENGLISH));
        alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isEqualTo("cn=go-daddy-secure-certificate-authority-g2_ou=httpcertsgodaddycomrepository_o=godaddycom_-inc_l=scottsdale_st=arizona_c=us".toLowerCase(Locale.ENGLISH));
    }

    @Test
    void generateAliasForCertificate() {
        Certificate certificate = mock(Certificate.class);

        String alias = CertificateUtils.generateAlias(certificate);
        assertThat(alias).isNotBlank();
    }


    @Test
    void generateAliasForDuplicateCertificate() {
        X509Certificate certificate = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);

        when(certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName(X500Principal.CANONICAL)).thenReturn("cn=localhost");

        List<X509Certificate> certificates = IntStream.rangeClosed(0, 10)
                .mapToObj(index -> certificate)
                .collect(Collectors.toList());

        Map<String, X509Certificate> aliasToCertificate = CertificateUtils.generateAliases(certificates);
        assertThat(aliasToCertificate.get("cn=localhost")).isNotNull();
        assertThat(aliasToCertificate.get("cn=localhost-1")).isNotNull();
        assertThat(aliasToCertificate.get("cn=localhost-9")).isNotNull();

        List<String> expectedAliases = IntStream.rangeClosed(0, 9)
                .mapToObj(index -> "cn=localhost-" + index)
                .collect(Collectors.toCollection(ArrayList::new));
        expectedAliases.add(0, "cn=localhost");
        assertThat(aliasToCertificate.keySet()).containsExactlyInAnyOrderElementsOf(expectedAliases);
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
    void loadBinaryP7bCertificateChainFromClassPath() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(P7B_LOCATION + "google-com.p7b");
        assertThat(certificates).hasSize(4);
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
    void loadOneLinerCertificate() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "one-liner-github-certificate.pem");
        assertThat(certificates).hasSize(1);
    }

    @Test
    void loadOneLinerContainingMultipleCertificate() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "one-liner-multiple-certificates.pem");
        assertThat(certificates).hasSize(3);
    }

    @Test
    void useExistingInstanceOfCertificateExtractorUtilsWhenOnlyUsingUrl() {
        CertificateExtractingClient certificateExtractingClient = mock(CertificateExtractingClient.class);
        when(certificateExtractingClient.get(anyString())).thenReturn(Collections.emptyList());

        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, invocationOnMock -> {
            if ("getInstance".equals(invocationOnMock.getMethod().getName())) {
                return certificateExtractingClient;
            } else {
                return invocationOnMock.callRealMethod();
            }
        })) {
            CertificateUtils.getCertificatesFromExternalSourceAsPem("https://github.com");
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(1));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsWhenGetCertificatesFromExternalSource() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);

            CertificateUtils.getCertificatesFromExternalSource(proxy, "https://github.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, null);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsAndPasswordAuthenticationWhenGetCertificatesFromExternalSource() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);
            PasswordAuthentication passwordAuthentication = mock(PasswordAuthentication.class);

            CertificateUtils.getCertificatesFromExternalSource(proxy, passwordAuthentication, "https://github.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, passwordAuthentication);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsWhenGetCertificatesFromExternalSourceAsPem() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);

            CertificateUtils.getCertificatesFromExternalSourceAsPem(proxy, "https://github.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, null);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsAndPasswordAuthenticationWhenGetCertificatesFromExternalSourceAsPem() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);
            PasswordAuthentication passwordAuthentication = mock(PasswordAuthentication.class);

            CertificateUtils.getCertificatesFromExternalSourceAsPem(proxy, passwordAuthentication, "https://github.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, passwordAuthentication);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsWhenGetCertificatesFromExternalSources() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);

            CertificateUtils.getCertificatesFromExternalSources(proxy, "https://github.com", "https://stackoverflow.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, null);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsAndPasswordAuthenticationWhenGetCertificatesFromExternalSources() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);
            PasswordAuthentication passwordAuthentication = mock(PasswordAuthentication.class);

            CertificateUtils.getCertificatesFromExternalSources(proxy, passwordAuthentication, "https://github.com", "https://stackoverflow.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, passwordAuthentication);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsWhenGetCertificatesFromExternalSourcesAsPem() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);

            CertificateUtils.getCertificatesFromExternalSourcesAsPem(proxy, "https://github.com", "https://stackoverflow.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, null);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsWhenGetCertificatesFromExternalSourcesAsPemAndUrlsAsList() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);

            CertificateUtils.getCertificatesFromExternalSourcesAsPem(proxy, Arrays.asList("https://github.com", "https://stackoverflow.com"));

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, null);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsAndPasswordAuthenticationWhenGetCertificatesFromExternalSourcesAsPem() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);
            PasswordAuthentication passwordAuthentication = mock(PasswordAuthentication.class);

            CertificateUtils.getCertificatesFromExternalSourcesAsPem(proxy, passwordAuthentication, "https://github.com", "https://stackoverflow.com");

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, passwordAuthentication);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
    }

    @Test
    void createAnInstanceOfCertificateExtractorUtilsWithProxyDetailsAndPasswordAuthenticationWhenGetCertificatesFromExternalSourcesAsPemAndUrlsAsList() {
        Map<CertificateExtractingClient, List<Object>> constructorArgs = new HashMap<>();
        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, InvocationOnMock::callRealMethod);
             MockedConstruction<CertificateExtractingClient> mockedConstruction = mockConstruction(CertificateExtractingClient.class,
                (mock, context) -> constructorArgs.put(mock, new ArrayList<>(context.arguments())))) {
            Proxy proxy = mock(Proxy.class);
            PasswordAuthentication passwordAuthentication = mock(PasswordAuthentication.class);

            CertificateUtils.getCertificatesFromExternalSourcesAsPem(proxy, passwordAuthentication, Arrays.asList("https://github.com", "https://stackoverflow.com"));

            List<CertificateExtractingClient> constructed = mockedConstruction.constructed();
            assertThat(constructed).hasSize(1);

            CertificateExtractingClient certificateExtractingClient = constructed.get(0);
            assertThat(constructorArgs.get(certificateExtractingClient)).contains(true, proxy, passwordAuthentication);
            mockedStatic.verify(CertificateExtractingClient::getInstance, times(0));
        }
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
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows") || operatingSystem.contains("linux")) {
            assertThat(certificates).isNotEmpty();
        } else {
            fail();
        }
    }

    @Test
    void writeDerCertificate() throws IOException {
        List<Certificate> baseCertificates = CertificateUtils.loadCertificate(DER_LOCATION + "digicert.cer");
        assertThat(baseCertificates).hasSize(1);
        Certificate baseCertificate = baseCertificates.get(0);

        Path certificatePath = Paths.get(TestConstants.HOME_DIRECTORY).resolve(Paths.get("digicert.crt"));

        CertificateUtils.write(certificatePath, baseCertificate);

        assertThat(Files.exists(certificatePath)).isTrue();

        List<Certificate> certificates = CertificateUtils.loadCertificate(certificatePath);
        assertThat(certificates).hasSize(1);
        Certificate certificate = baseCertificates.get(0);
        assertThat(baseCertificate).isEqualTo(certificate);

        Files.delete(certificatePath);
    }

    @Test
    void writeDerCertificateThrowsExceptionWhenSomethingUnexpectedIsHappening() throws CertificateEncodingException {
        Path certificatePath = Paths.get(TestConstants.HOME_DIRECTORY).resolve(Paths.get("digicert.crt"));

        Certificate certificate = mock(Certificate.class);
        doThrow(new CertificateEncodingException("Kaboom!"))
                .when(certificate)
                .getEncoded();

        assertThatThrownBy(() -> CertificateUtils.write(certificatePath, certificate))
                .isInstanceOf(GenericCertificateException.class);

    }

    @Test
    void getSystemTrustedCertificatesDoesNotReturnCertificateIfNotACertificateEntry() throws KeyStoreException {
        KeyStore keyStore = mock(KeyStore.class);
        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class)) {
            keyStoreUtilsMockedStatic.when(KeyStoreUtils::loadSystemKeyStores).thenReturn(Collections.singletonList(keyStore));
            when(keyStore.aliases()).thenReturn(Collections.enumeration(Collections.singletonList("client")));
            when(keyStore.isCertificateEntry("client")).thenReturn(false);

            List<X509Certificate> certificates = CertificateUtils.getSystemTrustedCertificates();

            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getCertificatesReturnsEmptyWhenNonHttpsUrlIsProvided() {
        List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource("http://www.google.com/");

        assertThat(certificates).isEmpty();
    }

    @Test
    void getJdkTrustedCertificates() {
        List<X509Certificate> jdkTrustedCertificates = CertificateUtils.getJdkTrustedCertificates();

        assertThat(jdkTrustedCertificates).hasSizeGreaterThan(0);
    }

    @Test
    void isSelfSigned() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "self-signed.pem");

        assertThat(certificates).hasSize(1);
        Certificate certificate = certificates.get(0);

        boolean selfSigned = CertificateUtils.isSelfSigned(certificate);
        assertThat(selfSigned).isTrue();
    }

    @Test
    void isNotSelfSigned() {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "not-self-signed.pem");

        assertThat(certificates).hasSize(1);
        Certificate certificate = certificates.get(0);

        boolean selfSigned = CertificateUtils.isSelfSigned(certificate);
        assertThat(selfSigned).isFalse();
    }

    @Test
    void wrapCertificateExceptionIntoGenericCertificateExceptionWhenIsSelfSignedCallFails() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "not-self-signed.pem");
        assertThat(certificates).hasSize(1);
        Certificate certificate = spy(certificates.get(0));

        doThrow(new CertificateException("KABOOM!")).when(certificate).verify(any());

        assertThatThrownBy(() -> CertificateUtils.isSelfSigned(certificate))
                .isInstanceOf(GenericCertificateException.class);
    }

    @Test
    void wrapNoSuchAlgorithmExceptionIntoGenericCertificateExceptionWhenIsSelfSignedCallFails() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "not-self-signed.pem");
        assertThat(certificates).hasSize(1);
        Certificate certificate = spy(certificates.get(0));

        doThrow(new NoSuchAlgorithmException("KABOOM!")).when(certificate).verify(any());

        assertThatThrownBy(() -> CertificateUtils.isSelfSigned(certificate))
                .isInstanceOf(GenericCertificateException.class);
    }

    @Test
    void wrapInvalidKeyExceptionIntoGenericCertificateExceptionWhenIsSelfSignedCallFails() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "not-self-signed.pem");
        assertThat(certificates).hasSize(1);
        Certificate certificate = spy(certificates.get(0));

        doThrow(new InvalidKeyException("KABOOM!")).when(certificate).verify(any());

        assertThatThrownBy(() -> CertificateUtils.isSelfSigned(certificate))
                .isInstanceOf(GenericCertificateException.class);
    }

    @Test
    void wrapNoSuchProviderExceptionIntoGenericCertificateExceptionWhenIsSelfSignedCallFails() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "not-self-signed.pem");
        assertThat(certificates).hasSize(1);
        Certificate certificate = spy(certificates.get(0));

        doThrow(new NoSuchProviderException("KABOOM!")).when(certificate).verify(any());

        assertThatThrownBy(() -> CertificateUtils.isSelfSigned(certificate))
                .isInstanceOf(GenericCertificateException.class);
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
    void throwsGenericCertificateExceptionWhenCertificateIsNotFoundOnTheClasspath() {
        assertThatThrownBy(() -> CertificateUtils.loadCertificate("some-directory/some-certificate.pem"))
                .isInstanceOf(GenericIOException.class)
                .hasMessageContaining("Failed to load the certificate from the classpath for the given path: [some-directory/some-certificate.pem]");
    }

    @Test
    void throwsGenericCertificateExceptionWhenCertificateIsInputStreamIsNull() {
        assertThatThrownBy(() -> CertificateUtils.loadCertificate((InputStream) null))
                .isInstanceOf(GenericIOException.class)
                .hasMessageContaining("Failed to load the certificate from the provided InputStream because it is null");
    }

    @Test
    void throwsGenericCertificateExceptionWhenGettingCertificateEncodingException() throws CertificateEncodingException {
        X509Certificate certificate = mock(X509Certificate.class);

        doThrow(new CertificateEncodingException("KABOOM!")).when(certificate).getEncoded();

        assertThatThrownBy(() -> CertificateUtils.convertToPem(certificate))
                .isInstanceOf(GenericCertificateException.class)
                .hasMessage("java.security.cert.CertificateEncodingException: KABOOM!");
    }

    @Test
    void throwsUncheckedIOExceptionWhenUrlIsUnreachable() {
        assertThatThrownBy(() -> CertificateUtils.getCertificatesFromExternalSource("https://localhost:1234/"))
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

    @Test
    void returnEmptyListOfCertificatesWhenUnsupportedDataIsProvided() throws IOException {
        try(ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream("Hello".getBytes())) {
            List<Certificate> certificates = CertificateUtils.parseDerCertificate(byteArrayInputStream);

            assertThat(certificates).isEmpty();
        }
    }

    private Path copyFileToHomeDirectory(String path, String fileName) throws IOException {
        try (InputStream file = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TestConstants.HOME_DIRECTORY, fileName);
            Files.copy(Objects.requireNonNull(file), destination, REPLACE_EXISTING);
            return destination;
        }
    }

    private InputStream getResource(String path) {
        return this.getClass().getClassLoader().getResourceAsStream(path);
    }

}
