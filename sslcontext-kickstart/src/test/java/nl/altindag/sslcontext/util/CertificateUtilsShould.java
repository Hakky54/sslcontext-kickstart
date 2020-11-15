package nl.altindag.sslcontext.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static nl.altindag.sslcontext.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class CertificateUtilsShould {

    private static final String PEM_LOCATION = "pems-for-unit-tests/";
    private static final String TEMPORALLY_PEM_LOCATION = System.getProperty("user.home");

    @Test
    void generateAliasForX509Certificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
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
    void loadCertificateFromClassPath() throws CertificateException, IOException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(PEM_LOCATION + "badssl-certificate.pem");
        assertThat(certificates).hasSize(1);
    }

    @Test
    void loadMultipleCertificatesFromDifferentFiles() throws CertificateException, IOException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(
                PEM_LOCATION + "badssl-certificate.pem",
                PEM_LOCATION + "github-certificate.pem",
                PEM_LOCATION + "stackexchange.pem"
        );
        assertThat(certificates).hasSize(3);
    }

    @Test
    void loadCertificateFromDirectory() throws CertificateException, IOException {
        Path certificatePath = copyFileToHomeDirectory(PEM_LOCATION, "github-certificate.pem");
        List<Certificate> certificates = CertificateUtils.loadCertificate(certificatePath);

        assertThat(certificates).hasSize(1);

        Files.delete(certificatePath);
    }

    @Test
    void throwExceptionWhenLoadingCertificateFromUnknownPath() {
        Path certificatePath = Paths.get("somewhere-in-space.pem");
        assertThatThrownBy(() -> CertificateUtils.loadCertificate(certificatePath))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessage("java.nio.file.NoSuchFileException: somewhere-in-space.pem");
    }

    @Test
    void loadCertificateFromInputStream() throws CertificateException, IOException {
        List<Certificate> certificates;
        try(InputStream inputStream = getResource(PEM_LOCATION + "multiple-certificates.pem")) {
            certificates = CertificateUtils.loadCertificate(inputStream);
        }

        assertThat(certificates).hasSize(3);
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
