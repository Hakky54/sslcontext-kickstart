package nl.altindag.sslcontext.util;

import javax.net.ssl.X509TrustManager;

import static java.util.Objects.isNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class KeyStoreUtils {

    private static final char[] EMPTY_PASSWORD_PLACEHOLDER = null;
    private static final String KEYSTORE_TYPE = "PKCS12";

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

    public static <T extends X509TrustManager> KeyStore createTrustStore(T... trustManagers) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        for (T trustManager : trustManagers) {
            certificates.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
        }
        return createTrustStore(certificates);
    }

    public static <T extends Certificate> KeyStore createTrustStore(T... certificates) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return createTrustStore(Arrays.asList(certificates));
    }

    public static <T extends Certificate> KeyStore createTrustStore(List<T> certificates) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = createEmptyKeyStore();
        for (T certificate : certificates) {
            trustStore.setCertificateEntry(CertificateUtils.generateAlias(certificate), certificate);
        }
        return trustStore;
    }

    public static KeyStore createEmptyKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, EMPTY_PASSWORD_PLACEHOLDER);
        return keyStore;
    }

    public static List<KeyStore> loadSystemKeyStores() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        List<KeyStore> keyStores = new ArrayList<>();
        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("windows")) {
            KeyStore windowsRootKeyStore = loadSystemKeyStore("Windows-ROOT");
            KeyStore windowsMyKeyStore = loadSystemKeyStore("Windows-MY");

            keyStores.add(windowsRootKeyStore);
            keyStores.add(windowsMyKeyStore);
        }

        if (operatingSystem.contains("mac")) {
            KeyStore macKeyStore = loadSystemKeyStore("KeychainStore");
            keyStores.add(macKeyStore);
        }

        return keyStores;
    }

    private static KeyStore loadSystemKeyStore(String keyStoreType) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        return keyStore;
    }

}
