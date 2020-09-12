package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.exception.CertificateParseException;
import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.PrivateKeyParseException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
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

import static java.util.Objects.isNull;

/**
 * Reads PEM formatted private keys and certificates
 * as identity material and trust material
 */
public final class PemUtils {

    private static final char[] EMPTY_PASSWORD_PLACEHOLDER = null;

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_FACTORY_ALGORITHM = "RSA";
    private static final String CERTIFICATE_TYPE = "X.509";

    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";
    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    private PemUtils() {}

    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) {
        return loadTrustMaterial(certificatePath -> PemUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    @SafeVarargs
    private static <T> X509ExtendedTrustManager loadTrustMaterial(Function<T, InputStream> resourceMapper, T... resources) {
        try {
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
        } catch (KeyStoreException | IOException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    private static KeyStore createEmptyKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, null);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    private static Map<String, Certificate> parseCertificate(InputStream certificateStream) {
        String content = getStreamContent(certificateStream);
        return parseCertificate(content);
    }

    private static String getStreamContent(InputStream inputStream) {
        try (InputStreamReader inputStreamReader = new InputStreamReader(Objects.requireNonNull(inputStream), StandardCharsets.UTF_8);
             BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            return bufferedReader.lines()
                    .collect(Collectors.joining(NEW_LINE));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, Certificate> parseCertificate(String certificateContent) {
        try {
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
        } catch (IOException | CertificateException e) {
            throw new CertificateParseException(e);
        }
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

    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) {
        return loadTrustMaterial(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new UncheckedIOException(exception);
            }
        }, certificatePaths);
    }

    public static X509ExtendedTrustManager loadTrustMaterial(InputStream... certificateStreams) {
        return loadTrustMaterial(Function.identity(), certificateStreams);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String certificatePath, String privateKeyPath) {
        try (InputStream certificateStream = PemUtils.class.getClassLoader().getResourceAsStream(certificatePath);
             InputStream privateKeyStream = PemUtils.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            return loadIdentityMaterial(certificateStream, privateKeyStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateStream, InputStream privateKeyStream) {
        return loadIdentityMaterial(certificateStream, privateKeyStream, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateStream, InputStream privateKeyStream, char[] keyPassword) {
        String certificateContent = getStreamContent(certificateStream);
        String privateKeyContent = getStreamContent(privateKeyStream);
        return parseIdentityMaterial(certificateContent, privateKeyContent, keyPassword);
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(String certificateContent, String privateKeyContent, char[] keyPassword) {
        PrivateKey privateKey = parsePrivateKey(privateKeyContent, keyPassword);
        Certificate[] certificates = parseCertificate(certificateContent).values()
                .toArray(new Certificate[]{});

        return parseIdentityMaterial(certificates, privateKey);
    }

    private static PrivateKey parsePrivateKey(String identityContent, char[] keyPassword) {
        try {
            KeySpec keySpec = null;
            PEMParser pemParser = new PEMParser(new StringReader(identityContent));
            Object object = pemParser.readObject();

            if (object instanceof PrivateKeyInfo) {
                keySpec = new PKCS8EncodedKeySpec(((PrivateKeyInfo) object).getEncoded());
            }

            if (object instanceof PEMKeyPair) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
                KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
                return keyPair.getPrivate();
            }

            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                InputDecryptorProvider inputDecryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BOUNCY_CASTLE_PROVIDER)
                        .build(Objects.requireNonNull(keyPassword));

                PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(inputDecryptorProvider);
                keySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            }

            if (isNull(keySpec)) {
                throw new PrivateKeyParseException("Received an unsupported private key type");
            }

            KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (OperatorCreationException | PKCSException | InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            throw new PrivateKeyParseException(e);
        }
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(Certificate[] certificates, PrivateKey privateKey) {
        try {
            KeyStore keyStore = createEmptyKeyStore();
            keyStore.setKeyEntry(getCertificateAlias(certificates[0]), privateKey, null, certificates);
            return KeyManagerUtils.createKeyManager(keyStore, null);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificatePath, Path privateKeyPath) {
        return loadIdentityMaterial(certificatePath, privateKeyPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificatePath, Path privateKeyPath, char[] keyPassword) {
        try {
            try(InputStream certificateStream = Files.newInputStream(certificatePath, StandardOpenOption.READ);
                InputStream privateKeyStream = Files.newInputStream(privateKeyPath, StandardOpenOption.READ)) {
                return loadIdentityMaterial(certificateStream, privateKeyStream, keyPassword);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) {
        return loadIdentityMaterial(identityPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath, char[] keyPassword) {
        try {
            try(InputStream identityStream = PemUtils.class.getClassLoader().getResourceAsStream(identityPath)) {
                String identityContent = getStreamContent(identityStream);
                return parseIdentityMaterial(identityContent, identityContent, keyPassword);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) {
        return loadIdentityMaterial(identityPath, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath, char[] keyPassword) {
        try {
            try(InputStream identityStream = Files.newInputStream(identityPath)) {
                String identityContent = getStreamContent(identityStream);
                return parseIdentityMaterial(identityContent, identityContent, keyPassword);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream) {
        return loadIdentityMaterial(identityStream, EMPTY_PASSWORD_PLACEHOLDER);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream, char[] keyPassword) {
        String identityContent = getStreamContent(identityStream);
        return parseIdentityMaterial(identityContent, identityContent, keyPassword);
    }

}
