package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.PrivateKeyParseException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("SameParameterValue")
class PemUtilsShould {

    private static final String PEM_LOCATION = "pems-for-unit-tests/";
    private static final String TEMPORALLY_PEM_LOCATION = System.getProperty("user.home");

    @Test
    void loadSingleTrustMaterialFromClassPathAsSingleFile() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "github-certificate.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsMultipleFiles() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(
                PEM_LOCATION + "github-certificate.pem",
                PEM_LOCATION + "stackexchange.pem"
        );

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsSingleFile() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "multiple-certificates.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadSingleTrustMaterialWithPathFromDirectoryAsSingleFile() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        Files.delete(certificatePath);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsMultipleFiles() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        Path certificatePathOne = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");
        Path certificatePathTwo = copyFileToHomeDirectory(PEM_LOCATION, "stackexchange.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePathOne, certificatePathTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);

        Files.delete(certificatePathOne);
        Files.delete(certificatePathTwo);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsSingleFile() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
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
    void loadSingleTrustMaterialFromSingleInputStream() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "github-certificate.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromMultipleInputStream() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStreamOne = getResource(PEM_LOCATION + "github-certificate.pem");
            InputStream inputStreamTwo = getResource(PEM_LOCATION + "stackexchange.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStreamOne, inputStreamTwo);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromSingleInputStream() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "multiple-certificates.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromDirectory() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, PKCSException {
        Path identityPath = copyFileToHomeDirectory(PEM_LOCATION, "unencrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath);

        assertThat(keyManager).isNotNull();

        Files.delete(identityPath);
    }

    @Test
    void loadUnencryptedIdentityMaterialFromInputStream() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "unencrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream);
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromDirectory() throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "splitted-unencrypted-identity-containing-certificate.pem");
        Path privateKeyPath = copyFileToHomeDirectory(PEM_LOCATION, "splitted-unencrypted-identity-containing-private-key.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath);

        assertThat(keyManager).isNotNull();

        Files.delete(privateKeyPath);
        Files.delete(certificatePath);
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityInputStream() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        try(InputStream certificateStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
            InputStream privateKeyStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem")) {
            X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificateStream, privateKeyStream);
            assertThat(keyManager).isNotNull();
        }
    }

    @Test
    void loadEncryptedPrivateKeyAndCertificateAsIdentityFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem",
                "secret".toCharArray()
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaUnencryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "rsa-unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaEncryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-rsa-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcUnencryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-ec-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcEncryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-ec-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromClassPath() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-identity.pem", "secret".toCharArray());

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromDirectory() throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        Path identityPath = copyFileToHomeDirectory(PEM_LOCATION, "encrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath, "secret".toCharArray());

        assertThat(keyManager).isNotNull();

        Files.delete(identityPath);
    }

    @Test
    void loadEncryptedIdentityMaterialFromInputStream() throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "encrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream, "secret".toCharArray());
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPathWhichFirstContainsTheCertificate() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity-with-certificate-first.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void throwPrivateKeyParseExceptionWhenAnUnknownPrivateKeyHasBeenSupplied() throws IOException {
        try(InputStream inputStream = new ByteArrayInputStream("Hello there friend!".getBytes(StandardCharsets.UTF_8))) {
            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(inputStream))
                    .isInstanceOf(PrivateKeyParseException.class)
                    .hasMessage("Received an unsupported private key type");
        }
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
