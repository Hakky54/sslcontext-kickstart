package nl.altindag.sslcontext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import ch.qos.logback.classic.Level;
import nl.altindag.sslcontext.util.KeystoreUtils;
import nl.altindag.sslcontext.util.LogTestHelper;
import nl.altindag.sslcontext.util.TrustManagerUtils;

public class CompositeX509TrustManagerShould extends LogTestHelper<CompositeX509TrustManager> {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final String KEYSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void createCompositeX509TrustManagerFromKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStoreOne)
                                                                          .withTrustStore(trustStoreTwo)
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void createCompositeX509TrustManagerWithJdkTrustedCertificates() {
        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withDefaultJdkTrustStore(true)
                                                                          .build();

        assertThat(trustManager.getTrustManagers()).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    public void createCompositeX509TrustManagerWithKeyStoreAndTrustManagerAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStore, KeyManagerFactory.getDefaultAlgorithm())
                                                                          .build();

        assertThat(trustManager.getTrustManagers()).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createCompositeX509TrustManagerFromKeyStoreWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStoreOne, trustStoreTwo)
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void createCompositeX509TrustManagerFromListOfTrustManagersWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withX509TrustManagers(
                                                                                  Arrays.asList(TrustManagerUtils.createTrustManager(trustStoreOne),
                                                                                                TrustManagerUtils.createTrustManager(trustStoreTwo)))
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void checkClientTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = getTrustedX509Certificates(trustStore);

        CompositeX509TrustManager compositeX509TrustManager = new CompositeX509TrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509TrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    public void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = getTrustedX509Certificates(KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStore)
                                                                          .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    public void throwsExceptionWhenCheckServerTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = getTrustedX509Certificates(KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withX509TrustManager(TrustManagerUtils.createTrustManager(trustStore))
                                                                          .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this server certificate chain");

        List<String> logs = getLogs(Level.ERROR);
        assertThat(logs).containsExactly("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target");
    }

    @Test
    public void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = new CompositeX509TrustManager(Arrays.asList(
                TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore)));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void throwsExceptionWhenCheckClientTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = getTrustedX509Certificates(KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD));

        CompositeX509TrustManager compositeX509TrustManager = new CompositeX509TrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatThrownBy(() -> compositeX509TrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this client certificate chain");

        List<String> logs = getLogs(Level.ERROR);
        assertThat(logs).containsExactly("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target");
    }

    @Override
    protected Class<CompositeX509TrustManager> getTargetClass() {
        return CompositeX509TrustManager.class;
    }

    private X509Certificate[] getTrustedX509Certificates(KeyStore trustStore) throws KeyStoreException {
        List<X509Certificate> certificates = new ArrayList<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            Certificate certificate = trustStore.getCertificate(aliases.nextElement());
            if (certificate instanceof X509Certificate) {
                certificates.add((X509Certificate) certificate);
            }
        }

        return certificates.toArray(new X509Certificate[0]);
    }
}
