package nl.altindag.sslcontext.trustmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.security.KeyStore;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;

import org.junit.Test;

public class TrustManagerFactoryWrapperShould {

    @Test
    public void createTrustManagerFactoryWrapperWithCustomTrustManager() {
        TrustManager trustManager = new TrustManager() {};
        TrustManagerFactoryWrapper trustManagerFactoryWrapper = new TrustManagerFactoryWrapper(trustManager);

        assertThat(trustManagerFactoryWrapper).isNotNull();
        assertThat(trustManagerFactoryWrapper.getTrustManagers()).containsExactly(trustManager);
        assertThat(trustManagerFactoryWrapper.engineGetTrustManagers()).containsExactly(trustManager);
    }

    @Test
    public void engineInitWithKeyStoreDoesNothing() {
        TrustManagerFactoryWrapper trustManagerFactoryWrapper = new TrustManagerFactoryWrapper(null);

        assertThat(trustManagerFactoryWrapper).isNotNull();
        assertThatCode(() -> trustManagerFactoryWrapper.engineInit((KeyStore) null)).doesNotThrowAnyException();
    }

    @Test
    public void engineInitWithManagerFactoryParametersDoesNothing() {
        TrustManagerFactoryWrapper trustManagerFactoryWrapper = new TrustManagerFactoryWrapper(null);

        assertThat(trustManagerFactoryWrapper).isNotNull();
        assertThatCode(() -> trustManagerFactoryWrapper.engineInit((ManagerFactoryParameters) null)).doesNotThrowAnyException();
    }

}
