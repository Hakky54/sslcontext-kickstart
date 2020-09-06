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
import java.nio.file.StandardOpenOption;
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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Reads PEM formatted private keys and certificates
 * as identity material and trust material
 *
 * NOTE: There is currently limited support for reading
 *       the private keys. For now only unencrypted
 *       private keys are supported
 */
public final class PemUtils {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_FACTORY_ALGORITHM = "RSA";
    private static final String CERTIFICATE_TYPE = "X.509";
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);
    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";

    private PemUtils() {}

    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        return loadTrustMaterial(certificatePath -> PemUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    private static <T> X509ExtendedTrustManager loadTrustMaterial(Function<T, InputStream> resourceMapper, T... resources) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = createEmptyKeyStore();

        for (T resource : resources) {
            try (InputStream certificateStream = resourceMapper.apply(resource)) {
                Map<String, Certificate> certificates = parseCertificate(certificateStream);
                for (Map.Entry<String, Certificate> entry : certificates.entrySet()) {
                    trustStore.setCertificateEntry(entry.getKey(), entry.getValue());
                }
            }
        }

        return TrustManagerUtils.createTrustManager(trustStore);
    }

    private static KeyStore createEmptyKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, null);
        return keyStore;
    }

    private static Map<String, Certificate> parseCertificate(InputStream certificateStream) throws IOException, CertificateException {
        String content = getStreamContent(certificateStream);
        return parseCertificate(content);
    }

    private static String getStreamContent(InputStream inputStream) throws IOException {
        try(InputStreamReader inputStreamReader = new InputStreamReader(Objects.requireNonNull(inputStream), StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            return bufferedReader.lines()
                    .collect(Collectors.joining(NEW_LINE));
        }
    }

    private static Map<String, Certificate> parseCertificate(String certificateContent) throws IOException, CertificateException {
        Map<String, Certificate> certificates = new HashMap<>();
        Matcher certificateMatcher = CERTIFICATE_PATTERN.matcher(certificateContent);

        while (certificateMatcher.find()) {
            String sanitizedCertificate = certificateMatcher.group(1).replace(NEW_LINE, EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            try(ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
                Certificate certificate = certificateFactory.generateCertificate(certificateAsInputStream);
                certificates.put(getCertificateAlias(certificate), certificate);
            }
        }

        return certificates;
    }

    private static String getCertificateAlias(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName();
        } else {
            return UUID.randomUUID().toString();
        }
    }

    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        return loadTrustMaterial(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new RuntimeException(exception);
            }
        }, certificatePaths);
    }

    public static X509ExtendedTrustManager loadTrustMaterial(InputStream... certificateStreams) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return loadTrustMaterial(Function.identity(), certificateStreams);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String certificatePath, String privateKeyPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        try(InputStream certificateStream = PemUtils.class.getClassLoader().getResourceAsStream(certificatePath);
            InputStream privateKeyStream = PemUtils.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            return loadIdentityMaterial(certificateStream, privateKeyStream);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateStream, InputStream privateKeyStream) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        String certificateContent = getStreamContent(certificateStream);
        String privateKeyContent = getStreamContent(privateKeyStream);
        return parseIdentityMaterial(certificateContent, privateKeyContent);
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(String certificateContent, String privateKeyContent) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        PrivateKey privateKey = parsePrivateKey(privateKeyContent);
        Certificate[] certificates = parseCertificate(certificateContent).values()
                .toArray(new Certificate[]{});

        return parseIdentityMaterial(certificates, privateKey);
    }

    private static PrivateKey parsePrivateKey(String identityContent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyContent = null;
        Matcher privateKeyMatcher = PRIVATE_KEY_PATTERN.matcher(identityContent);
        if (privateKeyMatcher.find()) {
            privateKeyContent = privateKeyMatcher.group(1).replace(NEW_LINE, EMPTY).trim();
        }

        Objects.requireNonNull(privateKeyContent, "Received an unsupported private key type. " +
                "The private key should be wrapped between [-----BEGIN PRIVATE KEY-----] and [-----END PRIVATE KEY-----]");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(privateKeyContent)
        );

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
        return keyFactory.generatePrivate(keySpecPKCS8);
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(Certificate[] certificates, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore keyStore = createEmptyKeyStore();
        keyStore.setKeyEntry(getCertificateAlias(certificates[0]), privateKey, null, certificates);

        return KeyManagerUtils.createKeyManager(keyStore, null);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificatePath, Path privateKeyPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        try(InputStream certificateStream = Files.newInputStream(certificatePath, StandardOpenOption.READ);
            InputStream privateKeyStream = Files.newInputStream(privateKeyPath, StandardOpenOption.READ)) {
            return loadIdentityMaterial(certificateStream, privateKeyStream);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        try(InputStream identityStream = PemUtils.class.getClassLoader().getResourceAsStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        try(InputStream identityStream = Files.newInputStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        String identityContent = getStreamContent(identityStream);
        return parseIdentityMaterial(identityContent, identityContent);
    }

}
