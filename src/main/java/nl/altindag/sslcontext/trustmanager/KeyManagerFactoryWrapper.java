package nl.altindag.sslcontext.trustmanager;

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
    protected void engineInit(KeyStore keyStore, char[] password) throws Exception {}

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {}

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return keyManagers;
    }

}
