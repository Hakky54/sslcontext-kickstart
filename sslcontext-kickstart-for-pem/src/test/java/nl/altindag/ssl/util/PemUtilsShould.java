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

import nl.altindag.ssl.exception.CertificateParseException;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.exception.PrivateKeyParseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

/**
 * @author Hakan Altindag
 */
@SuppressWarnings("SameParameterValue")
@ExtendWith(MockitoExtension.class)
class PemUtilsShould {

    private static final String PEM_LOCATION = "pems-for-unit-tests/";
    private static final String TEST_RESOURCES_LOCATION = "src/test/resources/";

    @Test
    void parseSingleTrustMaterialFromContent() {
        String certificateContent = getResourceContent(PEM_LOCATION + "github-certificate.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void parseSingleTrustMaterialAsOpenSslTrustedCertificateFormatFromContent() {
        String certificateContent = getResourceContent(PEM_LOCATION + "alternative-certificate-type.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsMultipleStrings() {
        String certificateContentOne = getResourceContent(PEM_LOCATION + "github-certificate.pem");
        String certificateContentTwo = getResourceContent(PEM_LOCATION + "stackexchange.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContentOne, certificateContentTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsSingleString() {
        String certificateContent = getResourceContent(PEM_LOCATION + "multiple-certificates.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadSingleTrustMaterialFromClassPathAsSingleFile() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "github-certificate.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsMultipleFiles() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(
                PEM_LOCATION + "github-certificate.pem",
                PEM_LOCATION + "stackexchange.pem"
        );

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsSingleFile() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "multiple-certificates.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadSingleTrustMaterialWithPathFromDirectoryAsSingleFile() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION + "github-certificate.pem").toAbsolutePath();

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsMultipleFiles() {
        Path certificatePathOne = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "github-certificate.pem").toAbsolutePath();
        Path certificatePathTwo = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "stackexchange.pem").toAbsolutePath();

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePathOne, certificatePathTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsSingleFile() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "multiple-certificates.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadingNonExistingTrustMaterialFromDirectoryThrowsException() {
        Path nonExistingCertificate = Paths.get("somewhere-in-space.pem");
        assertThatThrownBy(() -> PemUtils.loadTrustMaterial(nonExistingCertificate))
                .isInstanceOf(GenericIOException.class)
                .hasMessageContaining("java.nio.file.NoSuchFileException: somewhere-in-space.pem");
    }

    @Test
    void loadSingleTrustMaterialFromSingleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "github-certificate.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromMultipleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStreamOne = getResource(PEM_LOCATION + "github-certificate.pem");
            InputStream inputStreamTwo = getResource(PEM_LOCATION + "stackexchange.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStreamOne, inputStreamTwo);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromSingleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "multiple-certificates.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "unencrypted-identity.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromInputStream() throws IOException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "unencrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream);
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromDirectory() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-certificate.pem").toAbsolutePath();
        Path privateKeyPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-private-key.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityInputStream() throws IOException {
        try(InputStream certificateStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
            InputStream privateKeyStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem")) {
            X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificateStream, privateKeyStream);
            assertThat(keyManager).isNotNull();
        }
    }

    @Test
    void loadEncryptedPrivateKeyAndCertificateAsIdentityFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem",
                "secret".toCharArray()
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "rsa-unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-rsa-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-ec-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-ec-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "encrypted-identity.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath, "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromInputStream() throws IOException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "encrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream, "secret".toCharArray());
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPathWhichFirstContainsTheCertificate() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity-with-certificate-first.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void parseEncryptedIdentityMaterialFromContent() {
        String identityContent = getResourceContent(PEM_LOCATION + "encrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void parseUnencryptedPrivateKeyAndCertificateAsIdentity() {
        String certificateContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
        String privateKeyContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem");

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(certificateContent, privateKeyContent, null);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void throwGenericIOExceptionWhenInputStreamCanNotBeClosed() throws IOException {
        InputStream certificateStream = spy(getResource(PEM_LOCATION + "github-certificate.pem"));

        doThrow(new IOException("KABOOM!!!"))
                .when(certificateStream)
                .close();

        assertThatThrownBy(() -> PemUtils.loadTrustMaterial(certificateStream))
                .isInstanceOf(GenericIOException.class)
                .hasRootCauseMessage("KABOOM!!!");
    }

    @Test
    void throwPrivateKeyParseExceptionWhenAnUnknownPrivateKeyHasBeenSupplied() throws IOException {
        try(InputStream inputStream = new ByteArrayInputStream("Hello there friend!".getBytes(StandardCharsets.UTF_8))) {
            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(inputStream))
                    .isInstanceOf(PrivateKeyParseException.class)
                    .hasMessage("Received an unsupported private key type");
        }
    }

    @Test
    void throwExceptionWhenParseTrustMaterialIsCalledWithoutValidCertificate() {
        assertThatThrownBy(() -> PemUtils.parseTrustMaterial(""))
                .isInstanceOf(CertificateParseException.class)
                .hasMessage("Received an unsupported certificate type");
    }

    @Test
    void throwPublicKeyParseExceptionWhenPublicKeyIsMissing() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"))
                .hasRootCauseInstanceOf(CertificateParseException.class)
                .hasMessageContaining("Received an unsupported certificate type");
    }

    @Test
    void throwGenericIOExceptionWhenStreamCannotBeClosed() throws IOException {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "unencrypted-identity.pem").toAbsolutePath();
        InputStream inputStream = spy(Files.newInputStream(identityPath, StandardOpenOption.READ));

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, InvocationOnMock::getMock)) {
            doThrow(new IOException("Could not close the stream")).when(inputStream).close();

            filesMockedStatic.when(() -> Files.newInputStream(any(Path.class), any(OpenOption.class))).thenReturn(inputStream);

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(identityPath))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("Could not close the stream");
        }
    }

    @Test
    void throwGenericIOExceptionWhenStreamCannotBeClosedForAnotherMethod() throws IOException {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-certificate.pem").toAbsolutePath();
        Path privateKeyPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-private-key.pem").toAbsolutePath();

        InputStream inputStream = spy(Files.newInputStream(privateKeyPath, StandardOpenOption.READ));

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, InvocationOnMock::getMock)) {
            doThrow(new IOException("Could not close the stream")).when(inputStream).close();

            filesMockedStatic.when(() -> Files.newInputStream(any(Path.class), any(OpenOption.class))).thenReturn(inputStream);

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("Could not close the stream");
        }
    }

    @Test
    void throwGenericIOExceptionWhenStreamCannotBeClosedForAnotherAnotherMethod() throws IOException {
        String certificatePath = PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem";
        String privateKeyPath = PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem";

        InputStream certificateStream = spy(getResource(certificatePath));
        InputStream privateKeyStream = spy(getResource(privateKeyPath));

        try (MockedStatic<PemUtils> pemUtilsMockedStatic = mockStatic(PemUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getResourceAsStream".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {

            doThrow(new IOException("Could not close the stream")).when(certificateStream).close();
            doThrow(new IOException("Could not close the stream")).when(privateKeyStream).close();
            pemUtilsMockedStatic.when(() -> PemUtils.getResourceAsStream(certificatePath)).thenReturn(certificateStream);
            pemUtilsMockedStatic.when(() -> PemUtils.getResourceAsStream(privateKeyPath)).thenReturn(privateKeyStream);

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("Could not close the stream");
        }
    }

    @Test
    void throwPrivateKeyParseExceptionWhenInvalidPrivateKeyContentIsSupplied() {
        String invalidPrivateKey = "" +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
                "FHeRMpMdlCLXw78iQ6HjJw==\n" +
                "-----END ENCRYPTED PRIVATE KEY-----";

        assertThatThrownBy(() -> PemUtils.parseIdentityMaterial(invalidPrivateKey, null))
                .isInstanceOf(PrivateKeyParseException.class)
                .hasMessageContaining("problem parsing ENCRYPTED PRIVATE KEY");
    }

    @Test
    void throwCertificateParseExceptionWhenInvalidCertificateContentIsSupplied() {
        String invalidCertificate = "" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MwdGrM6kt0lfJy/gvGVsgIKZocHdedPeECqAtq7FAJYanOsjNN9RbBOGhbwq0/FP\n" +
                "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
                "-----END CERTIFICATE-----";

        assertThatThrownBy(() -> PemUtils.parseTrustMaterial(invalidCertificate))
                .isInstanceOf(CertificateParseException.class);
    }

    @Test
    void throwGenericKeyStoreWhenSetKeyEntryThrowsKeyStoreException() throws KeyStoreException {
        KeyStore keyStore = mock(KeyStore.class);
        doThrow(new KeyStoreException("lazy")).when(keyStore).setKeyEntry(anyString(), any(Key.class), any(), any());

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {

            keyStoreUtilsMock.when(KeyStoreUtils::createKeyStore).thenReturn(keyStore);

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem"))
                    .hasCauseInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("lazy");
        }
    }

    private String getResourceContent(String path) {
        try(InputStream resource = getResource(path);
            InputStreamReader inputStreamReader = new InputStreamReader(resource, StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
            return bufferedReader.lines()
                    .collect(Collectors.joining("\n"));
        } catch (IOException e) {
           throw new UncheckedIOException(e);
        }
    }

    private InputStream getResource(String path) {
        return this.getClass().getClassLoader().getResourceAsStream(path);
    }

}
