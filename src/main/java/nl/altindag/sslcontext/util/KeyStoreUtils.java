package nl.altindag.sslcontext.util;

import static java.util.Objects.isNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public final class KeyStoreUtils {

    private KeyStoreUtils() {}

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try(InputStream keystoreInputStream = KeyStoreUtils.class.getClassLoader().getResourceAsStream(keystorePath)) {
            return loadKeyStore(keystoreInputStream, keystorePassword, keystoreType);
        }
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword, String keystoreType) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try(InputStream keystoreInputStream = Files.newInputStream(keystorePath, StandardOpenOption.READ)) {
            return loadKeyStore(keystoreInputStream, keystorePassword, keystoreType);
        }
    }

    private static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, String keystoreType) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (isNull(keystoreInputStream)) {
            throw new IOException("Could not find the keystore file");
        }

        KeyStore keystore = KeyStore.getInstance(keystoreType);
        keystore.load(keystoreInputStream, keystorePassword);
        return keystore;
    }

}
