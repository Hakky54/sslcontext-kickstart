package nl.altindag.thunderberry.sslcontext.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import nl.altindag.thunderberry.sslcontext.CompositeX509TrustManager;

public class TrustManagerUtilsShould {

    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final String KEYSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void getTrustManagersWithDefaultJdkTrustedCertificatesWhenProvidingNullAsTrustStore() {
        TrustManager[] trustManagers = TrustManagerUtils.getTrustManagers(null);

        assertThat(trustManagers).hasSize(1);
        assertThat(trustManagers[0]).isInstanceOf(CompositeX509TrustManager.class);
        CompositeX509TrustManager trustManager = (CompositeX509TrustManager) trustManagers[0];
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
        assertThat(trustManager.getTrustManagers()).hasSize(1);
    }

    @Test
    public void getDefaultJdkTrustManagerWhenCallingGetJdkDefaultTrustManager() {
        X509TrustManager trustManager = TrustManagerUtils.getJdkDefaultTrustManager();

        assertThat(trustManager).isNotNull();
        assertThat(trustManager).isInstanceOf(X509TrustManager.class);
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);

    }

    @Test
    public void getTrustManagersWhenProvidingACustomTrustStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD);
        TrustManager[] trustManagers = TrustManagerUtils.getTrustManagers(trustStore);

        assertThat(trustManagers).hasSize(1);
        assertThat(trustManagers[0]).isInstanceOf(CompositeX509TrustManager.class);
        CompositeX509TrustManager trustManager = (CompositeX509TrustManager) trustManagers[0];
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustManager.getTrustManagers()).hasSize(1);
    }

    @Test
    public void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.getTrustManager(trustStore, "ABCD"))
                .isInstanceOf(RuntimeException.class);
    }

}
