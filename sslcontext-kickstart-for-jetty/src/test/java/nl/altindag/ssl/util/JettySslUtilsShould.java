package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;

class JettySslUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";

    private static final char[] IDENTITY_PASSWORD = "secret".toCharArray();
    private static final char[] TRUSTSTORE_PASSWORD = "secret".toCharArray();
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void createJettySslContextFactoryForClientWithTrustMaterial() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isNotPresent();
        assertThat(sslFactory.getIdentities()).isEmpty();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEmpty();
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    void createJettySslContextFactoryForClientWithIdentityMaterialAndTrustMaterial() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore, TRUSTSTORE_PASSWORD)
                .withPasswordCaching()
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isPresent();
        assertThat(sslFactory.getIdentities()).isNotEmpty();
        assertThat(sslFactory.getIdentities().get(0).getKeyStorePassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    void createJettySslContextFactoryForServerWithIdentityMaterialAndTrustMaterial() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore, TRUSTSTORE_PASSWORD)
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isPresent();
        assertThat(sslFactory.getIdentities()).isNotEmpty();
        assertThat(sslFactory.getIdentities().get(0).getKeyStorePassword()).isEmpty();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustStores()).isNotEmpty();
        assertThat(sslFactory.getTrustStores().get(0).getKeyStorePassword()).isEmpty();
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Server sslContextFactory = JettySslUtils.forServer(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

}
