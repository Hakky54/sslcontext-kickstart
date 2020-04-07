package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.SSLFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
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

public class JettySslContextUtilsShould {

    @Test
    public void createJettySslContextFactoryForClientForOneWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
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

        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    public void createJettySslContextFactoryForClientForTwoWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
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

        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    public void createJettySslContextFactoryForServerForTwoWayAuthentication() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
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

        SslContextFactory.Server sslContextFactory = JettySslContextUtils.forServer(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    public void throwExceptionWhenCreatingJettySslContextFactoryForClientWithoutSslContext() {
        assertThatThrownBy(() -> JettySslContextUtils.forClient(SSLFactory.builder().build()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    public void throwExceptionWhenCreatingJettySslContextFactoryForServerWithoutSslContext() {
        assertThatThrownBy(() -> JettySslContextUtils.forServer(SSLFactory.builder().build()))
                .isInstanceOf(NullPointerException.class);
    }

}
