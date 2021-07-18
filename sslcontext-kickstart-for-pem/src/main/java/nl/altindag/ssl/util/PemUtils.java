/*
 * Copyright 2019-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.exception.CertificateParseException;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.exception.PrivateKeyParseException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Reads PEM formatted private keys and certificates
 * as identity material and trust material and maps it
 * to either a {@link X509ExtendedKeyManager} or {@link X509ExtendedTrustManager}.
 * <br>
 * <br>
 * The PemUtils provides also other methods for example to:
 * <pre>
 * - load trusted certificates and map it into a list of {@link X509Certificate}
 * - load identity material and map it into a {@link PrivateKey}
 * </pre>
 *
 * The PemUtils serves mainly as a helper class to easily supply the PEM formatted SSL material
 * for the {@link SSLFactory}, but can also be used for other purposes.
 *
 * @author Hakan Altindag
 */
public final class PemUtils {

    private static final char[] DUMMY_PASSWORD = KeyStoreUtils.DUMMY_PASSWORD.toCharArray();
    private static final char[] NO_PASSWORD = null;
    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
    private static final JcaX509CertificateConverter CERTIFICATE_CONVERTER = new JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
    private static final JceOpenSSLPKCS8DecryptorProviderBuilder OPEN_SSL_PKCS8_DECRYPTOR_PROVIDER_BUILDER = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BOUNCY_CASTLE_PROVIDER);
    private static final JcePEMDecryptorProviderBuilder PEM_DECRYPTOR_PROVIDER_BUILDER = new JcePEMDecryptorProviderBuilder().setProvider(BOUNCY_CASTLE_PROVIDER);
    private static final BouncyFunction<char[], InputDecryptorProvider> INPUT_DECRYPTOR_PROVIDER = password -> OPEN_SSL_PKCS8_DECRYPTOR_PROVIDER_BUILDER.build(Objects.requireNonNull(password));
    private static final BouncyFunction<char[], PEMDecryptorProvider> PEM_DECRYPTOR_PROVIDER = password -> PEM_DECRYPTOR_PROVIDER_BUILDER.build(Objects.requireNonNull(password));

    private PemUtils() {}

    /**
     * Loads certificates from the classpath and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) {
        return mapTrustMaterial(
                loadCertificate(certificatePaths)
        );
    }

    /**
     * Loads certificates from the filesystem and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) {
        return mapTrustMaterial(
                loadCertificate(certificatePaths)
        );
    }

    /**
     * Loads certificates from multiple InputStreams and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedTrustManager loadTrustMaterial(InputStream... certificateStreams) {
        return mapTrustMaterial(
                loadCertificate(certificateStreams)
        );
    }

    /**
     * Loads certificates from the classpath and maps it to a list of {@link X509Certificate}
     */
    public static List<X509Certificate> loadCertificate(String... certificatePaths) {
        return loadCertificate(certificatePaths, PemUtils::getResourceAsStream);
    }

    /**
     * Loads certificates from the filesystem and maps it to a list of {@link X509Certificate}
     */
    public static List<X509Certificate> loadCertificate(Path... certificatePaths) {
        return loadCertificate(certificatePaths, PemUtils::getFileAsStream);
    }

    /**
     * Loads certificates from multiple InputStreams and maps it a list of {@link X509Certificate}
     */
    public static List<X509Certificate> loadCertificate(InputStream... certificateStreams) {
        return loadCertificate(certificateStreams, Function.identity());
    }

    private static <T> List<X509Certificate> loadCertificate(T[] resources, Function<T, InputStream> resourceMapper) {
        return Arrays.stream(resources)
                .map(resourceMapper)
                .map(IOUtils::getContent)
                .map(PemUtils::parseCertificate)
                .flatMap(Collection::stream)
                .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    private static List<X509Certificate> parseCertificate(String certContent) {
        try {
            Reader stringReader = new StringReader(certContent);
            PEMParser pemParser = new PEMParser(stringReader);
            List<X509Certificate> certificates = new ArrayList<>();

            Object object = pemParser.readObject();
            while (object != null) {
                if (object instanceof X509CertificateHolder) {
                    X509Certificate certificate = CERTIFICATE_CONVERTER.getCertificate((X509CertificateHolder) object);
                    certificates.add(certificate);
                } else if (object instanceof X509TrustedCertificateBlock) {
                    X509CertificateHolder certificateHolder = ((X509TrustedCertificateBlock) object).getCertificateHolder();
                    X509Certificate certificate = CERTIFICATE_CONVERTER.getCertificate(certificateHolder);
                    certificates.add(certificate);
                }

                object = pemParser.readObject();
            }

            pemParser.close();
            stringReader.close();

            if (certificates.isEmpty()) {
                throw new CertificateParseException("Received an unsupported certificate type");
            }

            return certificates;
        } catch (IOException | CertificateException e) {
            throw new CertificateParseException(e);
        }
    }

    /**
     * Parses one or more certificates as a string representation
     * and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedTrustManager parseTrustMaterial(String... certificateContents) {
        return Arrays.stream(certificateContents)
                .map(PemUtils::parseCertificate)
                .flatMap(Collection::stream)
                .collect(Collectors.collectingAndThen(Collectors.toList(), PemUtils::mapTrustMaterial));
    }

    private static X509ExtendedTrustManager mapTrustMaterial(List<X509Certificate> certificates) {
        KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
        return TrustManagerUtils.createTrustManager(trustStore);
    }

    /**
     * Loads the identity material based on a certificate chain and a private key
     * from the classpath and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(String certificateChainPath, String privateKeyPath) {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, NO_PASSWORD);
    }

    /**
     * Loads the identity material based on a certificate chain and a private key from
     * the classpath and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(String certificateChainPath, String privateKeyPath, char[] keyPassword) {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, keyPassword, PemUtils::getResourceAsStream);
    }

    /**
     * Loads the identity material based on a certificate chain and a private key
     * as an InputStream and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateChainStream, InputStream privateKeyStream) {
        return loadIdentityMaterial(certificateChainStream, privateKeyStream, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateChainStream, InputStream privateKeyStream, char[] keyPassword) {
        return loadIdentityMaterial(certificateChainStream, privateKeyStream, keyPassword, Function.identity());
    }

    /**
     * Loads the identity material based on a certificate chain and a private key
     * from the filesystem and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificateChainPath, Path privateKeyPath) {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, NO_PASSWORD);
    }

    /**
     * Loads the identity material based on a certificate chain and a private key
     * from the filesystem and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificateChainPath, Path privateKeyPath, char[] keyPassword) {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, keyPassword, PemUtils::getFileAsStream);
    }

    /**
     * Loads the identity material based on a combined file containing the certificate chain and the private key
     * from the classpath and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) {
        return loadIdentityMaterial(identityPath, NO_PASSWORD);
    }

    /**
     * Loads the identity material based on a combined file containing the certificate chain and the private key
     * from the classpath and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath, char[] keyPassword) {
        return loadIdentityMaterial(identityPath, keyPassword, PemUtils::getResourceAsStream);
    }

    /**
     * Loads the identity material based on a combined file containing the certificate chain and the private key
     * from the filesystem and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) {
        return loadIdentityMaterial(identityPath, NO_PASSWORD);
    }

    /**
     * Loads the identity material based on a combined file containing the certificate chain and the private key
     * from the filesystem and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath, char[] keyPassword) {
        return loadIdentityMaterial(identityPath, keyPassword, PemUtils::getFileAsStream);
    }

    /**
     * Loads the identity material based on a combined entity containing the certificate chain and the private key
     * from an InputStream and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream) {
        return loadIdentityMaterial(identityStream, NO_PASSWORD);
    }

    /**
     * Loads the identity material based on a combined entity containing the certificate chain and the private key
     * from an InputStream and maps it to an instance of {@link X509ExtendedKeyManager}
     */
    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream, char[] keyPassword) {
        return loadIdentityMaterial(identityStream, keyPassword, Function.identity());
    }

    private static <T> X509ExtendedKeyManager loadIdentityMaterial(T certificateChain, T privateKey, char[] keyPassword, Function<T, InputStream> resourceMapper) {
        try(InputStream certificateChainStream = resourceMapper.apply(certificateChain);
            InputStream privateKeyStream = resourceMapper.apply(privateKey)) {

            String certificateChainContent = IOUtils.getContent(certificateChainStream);
            String privateKeyContent = IOUtils.getContent(privateKeyStream);

            return parseIdentityMaterial(certificateChainContent, privateKeyContent, keyPassword);
        } catch (IOException exception) {
            throw new GenericIOException(exception);
        }
    }

    private static <T> X509ExtendedKeyManager loadIdentityMaterial(T identity, char[] keyPassword, Function<T, InputStream> resourceMapper) {
        try(InputStream identityStream = resourceMapper.apply(identity)) {
            String identityContent = IOUtils.getContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent, keyPassword);
        } catch (IOException exception) {
            throw new GenericIOException(exception);
        }
    }

    /**
     * Parses the identity material based on a string representation containing the certificate chain and the private key
     * and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedKeyManager parseIdentityMaterial(String identityContent, char[] keyPassword) {
        return parseIdentityMaterial(identityContent, identityContent, keyPassword);
    }

    /**
     * Parses the identity material based on a string representation of the certificate chain and the private key
     * and maps it to an instance of {@link X509ExtendedTrustManager}
     */
    public static X509ExtendedKeyManager parseIdentityMaterial(String certificateChainContent, String privateKeyContent, char[] keyPassword) {
        PrivateKey privateKey = parsePrivateKey(privateKeyContent, keyPassword);
        Certificate[] certificateChain = PemUtils.parseCertificate(certificateChainContent)
                .toArray(new Certificate[]{});

        return parseIdentityMaterial(certificateChain, privateKey);
    }

    /**
     * Loads the private key from the classpath and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(String identityPath) {
        return loadPrivateKey(identityPath, NO_PASSWORD);
    }

    /**
     * Loads the private key from the classpath and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(String identityPath, char[] keyPassword) {
        return loadPrivateKey(identityPath, keyPassword, PemUtils::getResourceAsStream);
    }

    /**
     * Loads the private key from the filesystem and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(Path identityPath) {
        return loadPrivateKey(identityPath, NO_PASSWORD);
    }

    /**
     * Loads the private key from the filesystem and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(Path identityPath, char[] keyPassword) {
        return loadPrivateKey(identityPath, keyPassword, PemUtils::getFileAsStream);
    }

    /**
     * Loads the private key from an InputStream and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(InputStream identityStream) {
        return loadPrivateKey(identityStream, NO_PASSWORD);
    }

    /**
     * Loads the private key from an InputStream and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey loadPrivateKey(InputStream identityStream, char[] keyPassword) {
        return loadPrivateKey(identityStream, keyPassword, Function.identity());
    }

    private static <T> PrivateKey loadPrivateKey(T privateKey, char[] keyPassword, Function<T, InputStream> resourceMapper) {
        try(InputStream privateKeyStream = resourceMapper.apply(privateKey)) {
            String privateKeyContent = IOUtils.getContent(privateKeyStream);
            return parsePrivateKey(privateKeyContent, keyPassword);
        } catch (IOException exception) {
            throw new GenericIOException(exception);
        }
    }

    /**
     * Parses the private key based on a string representation of the private key
     * and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey parsePrivateKey(String identityContent) {
        return parsePrivateKey(identityContent, NO_PASSWORD);
    }

    /**
     * Parses the private key based on a string representation of the private key
     * and maps it to an instance of {@link PrivateKey}
     */
    public static PrivateKey parsePrivateKey(String identityContent, char[] keyPassword) {
        try {
            Reader stringReader = new StringReader(identityContent);
            PEMParser pemParser = new PEMParser(stringReader);
            PrivateKeyInfo privateKeyInfo = null;

            Object object = pemParser.readObject();

            while (object != null && privateKeyInfo == null) {
                if (object instanceof PrivateKeyInfo) {
                    privateKeyInfo = (PrivateKeyInfo) object;
                } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                    InputDecryptorProvider inputDecryptorProvider = INPUT_DECRYPTOR_PROVIDER.apply(keyPassword);
                    privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(inputDecryptorProvider);
                } else if (object instanceof PEMKeyPair) {
                    privateKeyInfo = ((PEMKeyPair) object).getPrivateKeyInfo();
                } else if (object instanceof PEMEncryptedKeyPair) {
                    PEMDecryptorProvider pemDecryptorProvider = PEM_DECRYPTOR_PROVIDER.apply(keyPassword);
                    PEMKeyPair pemKeyPair = ((PEMEncryptedKeyPair) object).decryptKeyPair(pemDecryptorProvider);
                    privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
                }

                if (privateKeyInfo == null) {
                    object = pemParser.readObject();
                }
            }

            pemParser.close();
            stringReader.close();

            if (Objects.isNull(privateKeyInfo)) {
                throw new PrivateKeyParseException("Received an unsupported private key type");
            }

            return KEY_CONVERTER.getPrivateKey(privateKeyInfo);
        } catch (OperatorCreationException | PKCSException | IOException e) {
            throw new PrivateKeyParseException(e);
        }
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(Certificate[] certificatesChain, PrivateKey privateKey) {
        try {
            KeyStore keyStore = KeyStoreUtils.createKeyStore();
            keyStore.setKeyEntry(CertificateUtils.generateAlias(certificatesChain[0]), privateKey, DUMMY_PASSWORD, certificatesChain);
            return KeyManagerUtils.createKeyManager(keyStore, DUMMY_PASSWORD);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    protected static InputStream getResourceAsStream(String name) {
        return PemUtils.class.getClassLoader().getResourceAsStream(name);
    }

    private static InputStream getFileAsStream(Path path) {
        try {
            return Files.newInputStream(path, StandardOpenOption.READ);
        } catch (IOException e) {
            throw new GenericIOException(e);
        }
    }

    @FunctionalInterface
    private interface BouncyFunction<T, R> {
        R apply(T t) throws OperatorCreationException;
    }

}
