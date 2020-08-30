package nl.altindag.sslcontext.util;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class PemUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);
    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";

    private PemUtils() {}

    /**
     * Reads a PEM formatted certificate file from the classpath
     */
    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        for (String certificatePath : certificatePaths) {
            try(InputStream certificateStream = PemUtils.class.getClassLoader().getResourceAsStream(certificatePath)) {
                Map<String, Certificate> certificates = parseCertificate(certificateStream);

                for (Map.Entry<String, Certificate> entry : certificates.entrySet()) {
                    trustStore.setCertificateEntry(entry.getKey(), entry.getValue());
                }
            }
        }

        return TrustManagerUtils.createTrustManager(trustStore);
    }

    /**
     * Reads a PEM formatted certificate file from the file system
     */
    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        for (Path certificatePath : certificatePaths) {
            try(InputStream certificateStream = Files.newInputStream(certificatePath)) {
                Map<String, Certificate> certificates = parseCertificate(certificateStream);

                for (Map.Entry<String, Certificate> entry : certificates.entrySet()) {
                    trustStore.setCertificateEntry(entry.getKey(), entry.getValue());
                }
            }
        }

        return TrustManagerUtils.createTrustManager(trustStore);
    }

    private static Map<String, Certificate> parseCertificate(InputStream certificateStream) throws IOException, CertificateException {
        String content = getStreamContent(certificateStream);
        return parseCertificate(content);
    }

    private static Map<String, Certificate> parseCertificate(String content) throws IOException, CertificateException {
        Map<String, Certificate> certificates = new HashMap<>();
        Matcher matcher = CERTIFICATE_PATTERN.matcher(content);

        while (matcher.find()) {
            byte[] certificateAsBytes = Base64.getDecoder().decode(matcher.group(1).replaceAll(NEW_LINE, EMPTY).trim());
            try(ByteArrayInputStream certificateAsByteArrayStream = new ByteArrayInputStream(certificateAsBytes)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
                Certificate certificate = certificateFactory.generateCertificate(certificateAsByteArrayStream);
                certificates.put(getCertificateAlias(certificate), certificate);
            }
        }

        return certificates;
    }

    /**
     * Reads an unencrypted PEM formatted key-pair file from the classpath
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        try(InputStream identityStream = PemUtils.class.getClassLoader().getResourceAsStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent);
        }
    }

    /**
     * Reads an unencrypted PEM formatted key-pair file from the file system
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        try(InputStream identityStream = Files.newInputStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent);
        }
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(String identityContent) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        String privateKeyContent = null;
        Matcher privateKeyMatcher = PRIVATE_KEY_PATTERN.matcher(identityContent);
        if (privateKeyMatcher.find()) {
            privateKeyContent = privateKeyMatcher.group(1).replaceAll(NEW_LINE, EMPTY).trim();
        }

        Certificate[] certificates = new ArrayList<>(parseCertificate(identityContent).values())
                .toArray(new Certificate[]{});

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(Objects.requireNonNull(privateKeyContent)));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(getCertificateAlias(certificates[0]), privateKey, null, certificates);

        return KeyManagerUtils.createKeyManager(keyStore, null);
    }

    private static String getStreamContent(InputStream inputStream) throws IOException {
        try(InputStreamReader inputStreamReader = new InputStreamReader(Objects.requireNonNull(inputStream), StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
            return bufferedReader.lines().collect(Collectors.joining(NEW_LINE));
        }
    }

    private static String getCertificateAlias(Certificate certificate) {
        String alias;
        if (certificate instanceof X509Certificate) {
            alias = ((X509Certificate) certificate).getSubjectX500Principal().getName();
        } else {
            alias = UUID.randomUUID().toString();
        }
        return alias;
    }
}
