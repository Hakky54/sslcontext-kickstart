package nl.altindag.sslcontext.keymanager;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.ManagerFactoryParameters;

import io.netty.handler.ssl.util.SimpleKeyManagerFactory;

public final class KeyManagerFactoryWrapper extends SimpleKeyManagerFactory {

    private final KeyManager[] keyManagers;

    public KeyManagerFactoryWrapper(KeyManager keyManager) {
        this.keyManagers = new KeyManager[] {keyManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore, char[] password) throws Exception {
        // Does not initialize engine with the provided keystore
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {
        // Does not initialize engine with the provided managerFactoryParameters
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return keyManagers;
    }

}
