package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.PrivateKeyParseException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
 */
public final class PemUtils {

    private static final char[] EMPTY_PASSWORD_PLACEHOLDER = null;

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String CERTIFICATE_TYPE = "X.509";
    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);

    private PemUtils() {}

    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return loadTrustMaterial(certificatePath -> PemUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    @SafeVarargs
    private static <T> X509ExtendedTrustManager loadTrustMaterial(Function<T, InputStream> resourceMapper, T... resources) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
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

    private static KeyStore createEmptyKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, EMPTY_PASSWORD_PLACEHOLDER);
        return keyStore;
    }

    private static Map<String, Certificate> parseCertificate(InputStream certificateStream) throws IOException, CertificateException {
        String content = getStreamContent(certificateStream);
        return parseCertificate(content);
    }

    private static String getStreamContent(InputStream inputStream) throws IOException {
        try (InputStreamReader inputStreamReader = new InputStreamReader(Objects.requireNonNull(inputStream), StandardCharsets.UTF_8);
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

    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return loadTrustMaterial(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new UncheckedIOException(exception);
            }
        }, certificatePaths);
    }

    public static X509ExtendedTrustManager loadTrustMaterial(InputStream... certificateStreams) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return loadTrustMaterial(Function.identity(), certificateStreams);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String certificatePath, String privateKeyPath) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        try (InputStream certificateStream = PemUtils.class.getClassLoader().getResourceAsStream(certificatePath);
             InputStream privateKeyStream = PemUtils.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            return loadIdentityMaterial(certificateStream, privateKeyStream);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateStream, InputStream privateKeyStream) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException, OperatorCreationException, KeyStoreException {
        return loadIdentityMaterial(certificateStream, privateKeyStream, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateStream, InputStream privateKeyStream, char[] keyPassword) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        String certificateContent = getStreamContent(certificateStream);
        String privateKeyContent = getStreamContent(privateKeyStream);
        return parseIdentityMaterial(certificateContent, privateKeyContent, keyPassword);
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(String certificateContent, String privateKeyContent, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, InvalidKeySpecException, OperatorCreationException, KeyStoreException {
        PrivateKey privateKey = parsePrivateKey(privateKeyContent, keyPassword);
        Certificate[] certificates = parseCertificate(certificateContent).values()
                .toArray(new Certificate[]{});

        return parseIdentityMaterial(certificates, privateKey);
    }

    private static PrivateKey parsePrivateKey(String identityContent, char[] keyPassword) throws IOException, PKCSException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        PEMParser pemParser = new PEMParser(new StringReader(identityContent));
        Object object = pemParser.readObject();

        PrivateKeyInfo privateKeyInfo;
        if (object instanceof PrivateKeyInfo) {
            privateKeyInfo = (PrivateKeyInfo) object;
        } else if (object instanceof PEMKeyPair) {
            privateKeyInfo = ((PEMKeyPair) object).getPrivateKeyInfo();
        } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
            InputDecryptorProvider inputDecryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .setProvider(BOUNCY_CASTLE_PROVIDER)
                    .build(Objects.requireNonNull(keyPassword));

            privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(inputDecryptorProvider);
        } else if (object instanceof PEMEncryptedKeyPair) {
            PEMDecryptorProvider pemDecryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(BOUNCY_CASTLE_PROVIDER)
                    .build(keyPassword);

            PEMKeyPair pemKeyPair = ((PEMEncryptedKeyPair) object).decryptKeyPair(pemDecryptorProvider);
            privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
        } else {
            throw new PrivateKeyParseException("Received an unsupported private key type");
        }

        return KEY_CONVERTER.getPrivateKey(privateKeyInfo);
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(Certificate[] certificates, PrivateKey privateKey) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = createEmptyKeyStore();
        keyStore.setKeyEntry(getCertificateAlias(certificates[0]), privateKey, EMPTY_PASSWORD_PLACEHOLDER, certificates);
        return KeyManagerUtils.createKeyManager(keyStore, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificatePath, Path privateKeyPath) throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, PKCSException, InvalidKeySpecException, KeyStoreException {
        return loadIdentityMaterial(certificatePath, privateKeyPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificatePath, Path privateKeyPath, char[] keyPassword) throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, PKCSException, OperatorCreationException, KeyStoreException {
        try(InputStream certificateStream = Files.newInputStream(certificatePath, StandardOpenOption.READ);
            InputStream privateKeyStream = Files.newInputStream(privateKeyPath, StandardOpenOption.READ)) {
            return loadIdentityMaterial(certificateStream, privateKeyStream, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException, InvalidKeySpecException {
        return loadIdentityMaterial(identityPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException, InvalidKeySpecException {
        try(InputStream identityStream = PemUtils.class.getClassLoader().getResourceAsStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException, InvalidKeySpecException {
        return loadIdentityMaterial(identityPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException, InvalidKeySpecException {
        try(InputStream identityStream = Files.newInputStream(identityPath)) {
            String identityContent = getStreamContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException, InvalidKeySpecException {
        return loadIdentityMaterial(identityStream, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException, InvalidKeySpecException {
        String identityContent = getStreamContent(identityStream);
        return parseIdentityMaterial(identityContent, identityContent, keyPassword);
    }

}
