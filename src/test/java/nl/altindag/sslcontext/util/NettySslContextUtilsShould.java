package nl.altindag.sslcontext.util;

import io.netty.handler.ssl.SslContext;
import nl.altindag.sslcontext.SSLFactory;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static nl.altindag.sslcontext.TestConstants.IDENTITY_FILE_NAME;
import static nl.altindag.sslcontext.TestConstants.IDENTITY_PASSWORD;
import static nl.altindag.sslcontext.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class NettySslContextUtilsShould {

    @Test
    public void createNettySslContextBuilderForClientForOneWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThat(sslFactory.isSecurityEnabled()).isTrue();
        assertThat(sslFactory.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslFactory.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isNull();
        assertThat(sslFactory.getKeyManagerFactory()).isNull();
        assertThat(sslFactory.getIdentities()).isEmpty();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustManagerFactory()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();
        assertThat(sslFactory.getSslContext().getProtocol()).isEqualTo("TLSv1.2");
        assertThat(sslFactory.getLayeredConnectionSocketFactory()).isNotNull();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        assertThat(sslContext.isClient()).isTrue();
        assertThat(sslContext.isServer()).isFalse();
        assertThat(sslContext.cipherSuites()).containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
    }

    @Test
    public void createNettySslContextBuilderForClientForTwoWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentity(identity, IDENTITY_PASSWORD)
                .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThat(sslFactory.isSecurityEnabled()).isTrue();
        assertThat(sslFactory.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslFactory.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isNotNull();
        assertThat(sslFactory.getKeyManagerFactory()).isNotNull();
        assertThat(sslFactory.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslFactory.getIdentities()).isNotEmpty();
        assertThat(sslFactory.getIdentities().get(0).getKeyStorePassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustManagerFactory()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();
        assertThat(sslFactory.getSslContext().getProtocol()).isEqualTo("TLSv1.2");
        assertThat(sslFactory.getLayeredConnectionSocketFactory()).isNotNull();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        assertThat(sslContext.isClient()).isTrue();
        assertThat(sslContext.isServer()).isFalse();
        assertThat(sslContext.cipherSuites()).containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
    }

    @Test
    public void createNettySslContextBuilderForServerForTwoWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentity(identity, IDENTITY_PASSWORD)
                .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThat(sslFactory.isSecurityEnabled()).isTrue();
        assertThat(sslFactory.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslFactory.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isNotNull();
        assertThat(sslFactory.getKeyManagerFactory()).isNotNull();
        assertThat(sslFactory.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslFactory.getIdentities()).isNotEmpty();
        assertThat(sslFactory.getIdentities().get(0).getKeyStorePassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustManagerFactory()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();
        assertThat(sslFactory.getSslContext().getProtocol()).isEqualTo("TLSv1.2");
        assertThat(sslFactory.getLayeredConnectionSocketFactory()).isNotNull();

        SslContext sslContext = NettySslContextUtils.forServer(sslFactory).build();
        assertThat(sslContext.isClient()).isFalse();
        assertThat(sslContext.isServer()).isTrue();
        assertThat(sslContext.cipherSuites()).containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
    }

    @Test
    public void throwExceptionWhenCreatingNettySslContextBuilderForClientWithoutTrustStore() {
        assertThatThrownBy(() -> NettySslContextUtils.forClient(SSLFactory.builder().build()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    public void throwExceptionWhenCreatingNettySslContextBuilderForServerWithoutIdentityAndWithoutTrustStore() {
        assertThatThrownBy(() -> NettySslContextUtils.forServer(SSLFactory.builder().build()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    public void throwExceptionWhenCreatingNettySslContextBuilderForServerWithoutIdentity() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThatThrownBy(() -> NettySslContextUtils.forServer(sslFactory))
                .isInstanceOf(NullPointerException.class);

    }

}
