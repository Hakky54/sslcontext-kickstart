package nl.altindag.sslcontext.trustmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import nl.altindag.sslcontext.util.KeystoreUtils;

public class UnsafeTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final String KEYSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void notThrowExceptionWhenValidatingCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    public void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();
    }

}
