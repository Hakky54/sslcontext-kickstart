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

import nl.altindag.ssl.exception.PrivateKeyParseException;
import nl.altindag.ssl.exception.PublicKeyParseException;
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
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Reads PEM formatted private keys and certificates
 * as identity material and trust material
 *
 * @author Hakan Altindag
 */
public final class PemUtils {

    private static final char[] DUMMY_PASSWORD = KeyStoreUtils.DUMMY_PASSWORD.toCharArray();
    private static final char[] NO_PASSWORD = null;
    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);

    private PemUtils() {}

    public static X509ExtendedTrustManager loadTrustMaterial(String... certificatePaths) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return mapTrustMaterial(CertificateUtils.loadCertificate(certificatePaths));
    }

    public static X509ExtendedTrustManager loadTrustMaterial(Path... certificatePaths) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return mapTrustMaterial(CertificateUtils.loadCertificate(certificatePaths));
    }

    public static X509ExtendedTrustManager loadTrustMaterial(InputStream... certificateStreams) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return mapTrustMaterial(CertificateUtils.loadCertificate(certificateStreams));
    }

    public static X509ExtendedTrustManager parseTrustMaterial(String... certificateContents) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        List<Certificate> certificates = new ArrayList<>();
        for (String certificateContent : certificateContents) {
            certificates.addAll(CertificateUtils.parseCertificate(certificateContent));
        }
        return mapTrustMaterial(certificates);
    }

    private static X509ExtendedTrustManager mapTrustMaterial(List<Certificate> certificates) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
        return TrustManagerUtils.createTrustManager(trustStore);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String certificateChainPath, String privateKeyPath) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String certificateChainPath, String privateKeyPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        try (InputStream certificateChainStream = PemUtils.class.getClassLoader().getResourceAsStream(certificateChainPath);
             InputStream privateKeyStream = PemUtils.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            return loadIdentityMaterial(certificateChainStream, privateKeyStream, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateChainStream, InputStream privateKeyStream) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        return loadIdentityMaterial(certificateChainStream, privateKeyStream, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream certificateChainStream, InputStream privateKeyStream, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        String certificateChainContent = IOUtils.getContent(certificateChainStream);
        String privateKeyContent = IOUtils.getContent(privateKeyStream);
        return parseIdentityMaterial(certificateChainContent, privateKeyContent, keyPassword);
    }

    public static X509ExtendedKeyManager parseIdentityMaterial(String identityPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        return parseIdentityMaterial(identityPath, identityPath, keyPassword);
    }

    public static X509ExtendedKeyManager parseIdentityMaterial(String certificateChainContent, String privateKeyContent, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, PKCSException, OperatorCreationException, KeyStoreException {
        PrivateKey privateKey = parsePrivateKey(privateKeyContent, keyPassword);
        Certificate[] certificateChain = CertificateUtils.parseCertificate(certificateChainContent)
                .toArray(new Certificate[]{});

        return parseIdentityMaterial(certificateChain, privateKey);
    }

    private static PrivateKey parsePrivateKey(String identityContent, char[] keyPassword) throws IOException, PKCSException, OperatorCreationException {
        StringReader stringReader = new StringReader(identityContent);
        PEMParser pemParser = new PEMParser(stringReader);
        PrivateKeyInfo privateKeyInfo = null;

        Object object = pemParser.readObject();

        while (object != null && privateKeyInfo == null) {
            if (object instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) object;
            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                InputDecryptorProvider inputDecryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BOUNCY_CASTLE_PROVIDER)
                        .build(Objects.requireNonNull(keyPassword));

                privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(inputDecryptorProvider);
            } else if (object instanceof PEMKeyPair) {
                privateKeyInfo = ((PEMKeyPair) object).getPrivateKeyInfo();
            } else if (object instanceof PEMEncryptedKeyPair) {
                PEMDecryptorProvider pemDecryptorProvider = new JcePEMDecryptorProviderBuilder()
                        .setProvider(BOUNCY_CASTLE_PROVIDER)
                        .build(keyPassword);

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
    }

    private static X509ExtendedKeyManager parseIdentityMaterial(Certificate[] certificatesChain, PrivateKey privateKey) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        if (certificatesChain == null || certificatesChain.length == 0) {
            throw new PublicKeyParseException("Certificate chain is not present");
        }

        KeyStore keyStore = KeyStoreUtils.createKeyStore();
        keyStore.setKeyEntry(CertificateUtils.generateAlias(certificatesChain[0]), privateKey, DUMMY_PASSWORD, certificatesChain);
        return KeyManagerUtils.createKeyManager(keyStore, DUMMY_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificateChainPath, Path privateKeyPath) throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, PKCSException, KeyStoreException {
        return loadIdentityMaterial(certificateChainPath, privateKeyPath, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path certificateChainPath, Path privateKeyPath, char[] keyPassword) throws IOException, NoSuchAlgorithmException, CertificateException, PKCSException, OperatorCreationException, KeyStoreException {
        try(InputStream certificateChainStream = Files.newInputStream(certificateChainPath, StandardOpenOption.READ);
            InputStream privateKeyStream = Files.newInputStream(privateKeyPath, StandardOpenOption.READ)) {
            return loadIdentityMaterial(certificateChainStream, privateKeyStream, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        return loadIdentityMaterial(identityPath, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(String identityPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        try(InputStream identityStream = PemUtils.class.getClassLoader().getResourceAsStream(identityPath)) {
            String identityContent = IOUtils.getContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        return loadIdentityMaterial(identityPath, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(Path identityPath, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        try(InputStream identityStream = Files.newInputStream(identityPath)) {
            String identityContent = IOUtils.getContent(identityStream);
            return parseIdentityMaterial(identityContent, identityContent, keyPassword);
        }
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, OperatorCreationException, PKCSException {
        return loadIdentityMaterial(identityStream, NO_PASSWORD);
    }

    public static X509ExtendedKeyManager loadIdentityMaterial(InputStream identityStream, char[] keyPassword) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, PKCSException {
        String identityContent = IOUtils.getContent(identityStream);
        return parseIdentityMaterial(identityContent, identityContent, keyPassword);
    }

}
