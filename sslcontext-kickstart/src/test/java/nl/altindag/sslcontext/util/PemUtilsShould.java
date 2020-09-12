package nl.altindag.sslcontext.util;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("SameParameterValue")
class PemUtilsShould {

    private static final String PEM_LOCATION = "pems-for-unit-tests/";
    private static final String TEMPORALLY_PEM_LOCATION = System.getProperty("user.home");

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
    void loadSingleTrustMaterialWithPathFromDirectoryAsSingleFile() throws IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        Files.delete(certificatePath);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsMultipleFiles() throws IOException {
        Path certificatePathOne = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");
        Path certificatePathTwo = copyFileToHomeDirectory(PEM_LOCATION, "stackexchange.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePathOne, certificatePathTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);

        Files.delete(certificatePathOne);
        Files.delete(certificatePathTwo);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsSingleFile() throws IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "multiple-certificates.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);

        Files.delete(certificatePath);
    }

    @Test
    void loadingNonExistingTrustMaterialFromDirectoryThrowsException() {
        Path nonExistingCertificate = Paths.get("somewhere-in-space.pem");
        assertThatThrownBy(() -> PemUtils.loadTrustMaterial(nonExistingCertificate))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessage("java.nio.file.NoSuchFileException: somewhere-in-space.pem");
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
    void loadUnencryptedIdentityMaterialFromDirectory() throws IOException {
        Path identityPath = copyFileToHomeDirectory(PEM_LOCATION, "unencrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath);

        assertThat(keyManager).isNotNull();

        Files.delete(identityPath);
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
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromDirectory() throws IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "splitted-unencrypted-identity-containing-certificate.pem");
        Path privateKeyPath = copyFileToHomeDirectory(PEM_LOCATION, "splitted-unencrypted-identity-containing-private-key.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath);

        assertThat(keyManager).isNotNull();

        Files.delete(privateKeyPath);
        Files.delete(certificatePath);
    }

    @Test
    void loadRsaUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "rsa-unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromDirectory() throws IOException {
        Path identityPath = copyFileToHomeDirectory(PEM_LOCATION, "encrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath, "secret".toCharArray());

        assertThat(keyManager).isNotNull();

        Files.delete(identityPath);
    }

    @Test
    void loadEncryptedIdentityMaterialFromInputStream() throws IOException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "encrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream, "secret".toCharArray());
        }

        assertThat(keyManager).isNotNull();
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
