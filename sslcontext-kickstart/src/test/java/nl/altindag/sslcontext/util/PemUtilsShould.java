package nl.altindag.sslcontext.util;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;

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
    void loadSingleTrustMaterialWithPathFromDirectoryAsSingleFile() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        Files.delete(certificatePath);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsMultipleFiles() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Path certificatePathOne = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");
        Path certificatePathTwo = copyFileToHomeDirectory(PEM_LOCATION, "stackexchange.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePathOne, certificatePathTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);

        Files.delete(certificatePathOne);
        Files.delete(certificatePathTwo);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsSingleFile() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "multiple-certificates.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);

        Files.delete(certificatePath);
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPath() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromDirectory() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Path identityPath = copyFileToHomeDirectory(PEM_LOCATION, "unencrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath);

        assertThat(keyManager).isNotNull();

        Files.delete(identityPath);
    }

    private Path copyFileToHomeDirectory(String path, String fileName) throws IOException {
        try (InputStream file = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TEMPORALLY_PEM_LOCATION, fileName);
            Files.copy(Objects.requireNonNull(file), destination, REPLACE_EXISTING);
            return destination;
        }
    }

}
