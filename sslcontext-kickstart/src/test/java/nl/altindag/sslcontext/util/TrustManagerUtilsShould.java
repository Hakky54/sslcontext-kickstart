package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TrustManagerUtilsShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void combineTrustManagers() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne), TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    public void combineTrustManagersWithTrustStoreHolders() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        KeyStoreHolder trustStoreHolderOne = new KeyStoreHolder(trustStoreOne, TRUSTSTORE_PASSWORD);
        KeyStoreHolder trustStoreHolderTwo = new KeyStoreHolder(trustStoreTwo, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreHolderOne, trustStoreHolderTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    public void combineTrustManagersWithKeyStores() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne, trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    public void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createTrustManagerWithJdkTrustedCertificatesWhenProvidingNullAsTrustStore() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager((KeyStore) null);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    public void createTrustManagerWithJdkTrustedCertificatesWhenCallingCreateTrustManagerWithJdkTrustedCertificates() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    public void createTrustManagerWhenProvidingACustomTrustStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, "ABCD"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

}
