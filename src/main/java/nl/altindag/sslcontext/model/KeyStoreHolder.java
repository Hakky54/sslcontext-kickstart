package nl.altindag.sslcontext.model;

import java.security.KeyStore;

public class KeyStoreHolder {

    private KeyStore keyStore;
    private char[] keyStorePassword;

    public KeyStoreHolder(KeyStore keyStore, char[] keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

}
