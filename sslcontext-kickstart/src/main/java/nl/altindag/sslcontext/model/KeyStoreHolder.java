package nl.altindag.sslcontext.model;

import java.security.KeyStore;

public final class KeyStoreHolder {

    private final KeyStore keyStore;
    private char[] keyStorePassword = {};
    private char[] keyPassword = {};

    public KeyStoreHolder(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public KeyStoreHolder(KeyStore keyStore, char[] keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
    }

    public KeyStoreHolder(KeyStore keyStore, char[] keyStorePassword, char[] keyPassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
        this.keyPassword = keyPassword;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    public char[] getKeyPassword() {
        return keyPassword;
    }

}
