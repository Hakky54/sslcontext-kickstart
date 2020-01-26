package nl.altindag.sslcontext.trustmanager;

import java.security.KeyStore;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;

import io.netty.handler.ssl.util.SimpleTrustManagerFactory;

public final class TrustManagerFactoryWrapper extends SimpleTrustManagerFactory {

    private final TrustManager[] trustManagers;

    public TrustManagerFactoryWrapper(final TrustManager trustManager) {
        this.trustManagers = new TrustManager[] {trustManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore) throws Exception { }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {}

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return trustManagers;
    }

}
