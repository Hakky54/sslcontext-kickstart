package nl.altindag.sslcontext.keymanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import javax.net.ssl.KeyManager;

import org.junit.Test;

public class KeyManagerFactoryWrapperShould {

    @Test
    public void createKeyManagerFactoryWrapperWithCustomTrustManager() {
        KeyManager keyManager = new KeyManager() {};
        KeyManagerFactoryWrapper keyManagerFactoryWrapper = new KeyManagerFactoryWrapper(keyManager);

        assertThat(keyManagerFactoryWrapper).isNotNull();
        assertThat(keyManagerFactoryWrapper.getKeyManagers()).containsExactly(keyManager);
        assertThat(keyManagerFactoryWrapper.engineGetKeyManagers()).containsExactly(keyManager);
    }

    @Test
    public void engineInitWithKeyStoreDoesNothing() {
        KeyManagerFactoryWrapper keyManagerFactoryWrapper = new KeyManagerFactoryWrapper(null);

        assertThat(keyManagerFactoryWrapper).isNotNull();
        assertThatCode(() -> keyManagerFactoryWrapper.engineInit(null, new char[]{})).doesNotThrowAnyException();
    }

    @Test
    public void engineInitWithManagerFactoryParametersDoesNothing() {
        KeyManagerFactoryWrapper keyManagerFactoryWrapper = new KeyManagerFactoryWrapper(null);

        assertThat(keyManagerFactoryWrapper).isNotNull();
        assertThatCode(() -> keyManagerFactoryWrapper.engineInit(null)).doesNotThrowAnyException();
    }

}
