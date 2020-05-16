package nl.altindag.sslcontext.trustmanager;

import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class CompositeX509ExtendedTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[]{'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final char[] KEYSTORE_PASSWORD = new char[]{'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    private static final Socket SOCKET = new Socket();
    private static final SSLEngine SSL_ENGINE = new MockedSSLEngine();

    @Test
    public void createCompositeX509TrustManagerFromKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStoreOne)
                .withTrustStores(trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.size()).isEqualTo(2);
    }

    @Test
    public void createCompositeX509TrustManagerWithKeyStoreAndTrustManagerAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStore(trustStore, KeyManagerFactory.getDefaultAlgorithm())
                .build();

        assertThat(trustManager.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createCompositeX509TrustManagerWithKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStore(trustStore)
                .build();

        assertThat(trustManager.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createCompositeX509TrustManagerFromKeyStoreWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStoreOne, trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.size()).isEqualTo(2);
    }

    @Test
    public void createCompositeX509TrustManagerFromListOfTrustManagersWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(
                        Arrays.asList(TrustManagerUtils.createTrustManager(trustStoreOne),
                                TrustManagerUtils.createTrustManager(trustStoreTwo)))
                .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.size()).isEqualTo(2);
    }

    @Test
    public void checkClientTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkClientTrustedWithSslEngine() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkClientTrustedWithSocket() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SOCKET))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkClientTrustedLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    public void checkClientTrustedWithSslEngineLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    public void checkClientTrustedWithSocketLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SOCKET))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    public void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkServerTrustedWithSslEngine() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkServerTrustedWithSocket() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SOCKET))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkServerTrustedLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    public void checkServerTrustedWithSslEngineLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    public void checkServerTrustedWithSocketLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509ExtendedTrustManager> logCaptor = LogCaptor.forClass(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SOCKET))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Received the following server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    public void throwsExceptionWhenCheckServerTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(TrustManagerUtils.createTrustManager(trustStore))
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    @Test
    public void throwsExceptionWhenCheckServerTrustedWithSslEngineDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(TrustManagerUtils.createTrustManager(trustStore))
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    @Test
    public void throwsExceptionWhenCheckServerTrustedWithSocketDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(TrustManagerUtils.createTrustManager(trustStore))
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", SOCKET))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    @Test
    public void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = new CompositeX509ExtendedTrustManager(Arrays.asList(
                TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore)));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void throwsExceptionWhenCheckClientTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatThrownBy(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    @Test
    public void throwsExceptionWhenCheckClientTrustedWithSslEngineDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatThrownBy(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SSL_ENGINE))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    @Test
    public void throwsExceptionWhenCheckClientTrustedWithSocketDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD));

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = new CompositeX509ExtendedTrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatThrownBy(() -> compositeX509ExtendedTrustManager.checkClientTrusted(trustedCerts, "RSA", SOCKET))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain");
    }

    static class MockedSSLEngine extends SSLEngine {
        @Override
        public SSLEngineResult wrap(ByteBuffer[] byteBuffers, int i, int i1, ByteBuffer byteBuffer) throws SSLException {
            return null;
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers, int i, int i1) throws SSLException {
            return null;
        }

        @Override
        public Runnable getDelegatedTask() {
            return null;
        }

        @Override
        public void closeInbound() throws SSLException {

        }

        @Override
        public boolean isInboundDone() {
            return false;
        }

        @Override
        public void closeOutbound() {

        }

        @Override
        public boolean isOutboundDone() {
            return false;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        @Override
        public void setEnabledCipherSuites(String[] strings) {

        }

        @Override
        public String[] getSupportedProtocols() {
            return new String[0];
        }

        @Override
        public String[] getEnabledProtocols() {
            return new String[0];
        }

        @Override
        public void setEnabledProtocols(String[] strings) {

        }

        @Override
        public SSLSession getSession() {
            return null;
        }

        @Override
        public void beginHandshake() throws SSLException {

        }

        @Override
        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return null;
        }

        @Override
        public SSLSession getHandshakeSession() {
            return new SSLSession() {
                @Override
                public byte[] getId() {
                    return new byte[0];
                }

                @Override
                public SSLSessionContext getSessionContext() {
                    return null;
                }

                @Override
                public long getCreationTime() {
                    return 0;
                }

                @Override
                public long getLastAccessedTime() {
                    return 0;
                }

                @Override
                public void invalidate() {

                }

                @Override
                public boolean isValid() {
                    return false;
                }

                @Override
                public void putValue(String s, Object o) {

                }

                @Override
                public Object getValue(String s) {
                    return null;
                }

                @Override
                public void removeValue(String s) {

                }

                @Override
                public String[] getValueNames() {
                    return new String[0];
                }

                @Override
                public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                    return new Certificate[0];
                }

                @Override
                public Certificate[] getLocalCertificates() {
                    return new Certificate[0];
                }

                @Override
                public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                    return new javax.security.cert.X509Certificate[0];
                }

                @Override
                public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                    return null;
                }

                @Override
                public Principal getLocalPrincipal() {
                    return null;
                }

                @Override
                public String getCipherSuite() {
                    return null;
                }

                @Override
                public String getProtocol() {
                    return "TLSv1.2";
                }

                @Override
                public String getPeerHost() {
                    return null;
                }

                @Override
                public int getPeerPort() {
                    return 0;
                }

                @Override
                public int getPacketBufferSize() {
                    return 0;
                }

                @Override
                public int getApplicationBufferSize() {
                    return 0;
                }
            };
        }

        @Override
        public void setUseClientMode(boolean b) {

        }

        @Override
        public boolean getUseClientMode() {
            return false;
        }

        @Override
        public void setNeedClientAuth(boolean b) {

        }

        @Override
        public boolean getNeedClientAuth() {
            return false;
        }

        @Override
        public void setWantClientAuth(boolean b) {

        }

        @Override
        public boolean getWantClientAuth() {
            return false;
        }

        @Override
        public void setEnableSessionCreation(boolean b) {

        }

        @Override
        public boolean getEnableSessionCreation() {
            return false;
        }
    }

}
