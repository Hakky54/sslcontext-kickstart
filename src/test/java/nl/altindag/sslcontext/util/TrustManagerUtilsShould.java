package nl.altindag.sslcontext.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;

public class TrustManagerUtilsShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void combineTrustManagers() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne), TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    public void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createTrustManagerWithJdkTrustedCertificatesWhenProvidingNullAsTrustStore() {
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(null);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    public void createTrustManagerWithJdkTrustedCertificatesWhenCallingCreateTrustManagerWithJdkTrustedCertificates() {
        X509TrustManager trustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    public void createTrustManagerWhenProvidingACustomTrustStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, "ABCD"))
                .isInstanceOf(GenericKeyStoreException.class);
    }

}
