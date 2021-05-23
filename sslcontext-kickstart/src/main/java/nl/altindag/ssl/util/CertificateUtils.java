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
import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Hakan Altindag
 */
public final class CertificateUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String CERTIFICATE_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile(CERTIFICATE_HEADER + "(.*?)" + CERTIFICATE_FOOTER, Pattern.DOTALL);

    private static final String EMPTY = "";
    private static final String CERTIFICATE_AUTHORITY_ISSUERS_ID = "1.3.6.1.5.5.7.48.2";

    private static SSLSocketFactory unsafeSslSocketFactory = null;

    private CertificateUtils() {}

    public static String generateAlias(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName();
        } else {
            return UUID.randomUUID().toString();
        }
    }

    public static List<Certificate> loadCertificate(String... certificatePaths) {
        return loadCertificate(certificatePath -> CertificateUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    public static List<Certificate> loadCertificate(Path... certificatePaths) {
        return loadCertificate(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new UncheckedIOException(exception);
            }
        }, certificatePaths);
    }

    public static List<Certificate> loadCertificate(InputStream... certificateStreams) {
        return loadCertificate(Function.identity(), certificateStreams);
    }

    private static <T> List<Certificate> loadCertificate(Function<T, InputStream> resourceMapper, T[] resources) {
        List<Certificate> certificates = new ArrayList<>();
        for (T resource : resources) {
            try (InputStream certificateStream = resourceMapper.apply(resource)) {
                certificates.addAll(parseCertificate(certificateStream));
            } catch (Exception e) {
                throw new GenericIOException(e);
            }
        }

        return Collections.unmodifiableList(certificates);
    }

    private static List<Certificate> parseCertificate(InputStream certificateStream) {
        String content = IOUtils.getContent(certificateStream);
        return parseCertificate(content);
    }

    public static List<Certificate> parseCertificate(String certificateContent) {
        List<Certificate> certificates = new ArrayList<>();
        Matcher certificateMatcher = CERTIFICATE_PATTERN.matcher(certificateContent);

        while (certificateMatcher.find()) {
            String sanitizedCertificate = certificateMatcher.group(1).replace(System.lineSeparator(), EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            try(ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
                Certificate certificate = certificateFactory.generateCertificate(certificateAsInputStream);
                certificates.add(certificate);
            } catch (IOException | CertificateException e) {
                throw new GenericCertificateException(e);
            }
        }

        if (certificates.isEmpty()) {
            throw new GenericCertificateException(
                    String.format(
                        "There are no valid certificates present to parse. " +
                        "Please make sure to supply at least one valid pem formatted certificate containing the header %s and the footer %s",
                        CERTIFICATE_HEADER,
                        CERTIFICATE_FOOTER
                    )
            );
        }

        return Collections.unmodifiableList(certificates);
    }

    public static List<X509Certificate> getJdkTrustedCertificates() {
        return Collections.unmodifiableList(
                Arrays.asList(
                        TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates().getAcceptedIssuers()
                )
        );
    }

    public static List<X509Certificate> getSystemTrustedCertificates() {
        return TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates()
                .map(X509TrustManager::getAcceptedIssuers)
                .map(Arrays::asList)
                .map(Collections::unmodifiableList)
                .orElse(Collections.emptyList());
    }

    public static Map<String, List<String>> getCertificateAsPem(String... urls) {
        return getCertificateAsPem(Arrays.asList(urls));
    }

    public static Map<String, List<String>> getCertificateAsPem(List<String> urls) {
        Map<String, List<String>> certificates = CertificateUtils.getCertificate(urls)
                .entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> CertificateUtils.convertToPem(entry.getValue())));

        return Collections.unmodifiableMap(certificates);
    }

    public static Map<String, List<Certificate>> getCertificate(String... urls) {
        return CertificateUtils.getCertificate(Arrays.asList(urls));
    }

    public static Map<String, List<Certificate>> getCertificate(List<String> urls) {
        Map<String, List<Certificate>> certificates = new HashMap<>();
        for (String url : urls) {
            List<Certificate> serverCertificates = CertificateUtils.getCertificateFromExternalSource(url);
            certificates.put(url, serverCertificates);
        }
        return Collections.unmodifiableMap(certificates);
    }

    private static List<Certificate> getCertificateFromExternalSource(String url) {
        try {
            URL parsedUrl = new URL(url);
            if ("https".equalsIgnoreCase(parsedUrl.getProtocol())) {
                HttpsURLConnection connection = (HttpsURLConnection) parsedUrl.openConnection();
                SSLSocketFactory unsafeSslSocketFactory = CertificateUtils.getUnsafeSslSocketFactory();
                connection.setSSLSocketFactory(unsafeSslSocketFactory);
                connection.connect();

                Certificate[] serverCertificates = connection.getServerCertificates();
                List<X509Certificate> rootCa = CertificateUtils.getRootCaFromChainIfPossible(serverCertificates);

                List<Certificate> certificates = new ArrayList<>();
                certificates.addAll(Arrays.asList(serverCertificates));
                certificates.addAll(rootCa);

                connection.disconnect();
                return certificates.stream()
                        .distinct()
                        .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
            } else {
                return Collections.emptyList();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static SSLSocketFactory getUnsafeSslSocketFactory() {
        if (unsafeSslSocketFactory == null) {
            unsafeSslSocketFactory = SSLFactory.builder()
                    .withTrustingAllCertificatesWithoutValidation()
                    .build().getSslSocketFactory();
        }

        return unsafeSslSocketFactory;
    }

    static List<X509Certificate> getRootCaFromChainIfPossible(Certificate[] certificates) {
        if (certificates.length > 0 && certificates[certificates.length - 1] instanceof X509Certificate) {
            X509Certificate certificate = (X509Certificate) certificates[certificates.length - 1];
            String issuer = certificate.getIssuerX500Principal().getName();
            String subject = certificate.getSubjectX500Principal().getName();

            boolean isSelfSignedCertificate = issuer.equals(subject);
            if (!isSelfSignedCertificate) {
                return CertificateUtils.getRootCaIfPossible(certificate);
            }
        }
        return Collections.emptyList();
    }

    static List<X509Certificate> getRootCaIfPossible(X509Certificate x509Certificate) {
        List<X509Certificate> rootCaFromAuthorityInfoAccessExtension = CertificateUtils.getRootCaFromAuthorityInfoAccessExtensionIfPresent(x509Certificate);
        if (!rootCaFromAuthorityInfoAccessExtension.isEmpty()) {
            return rootCaFromAuthorityInfoAccessExtension;
        }

        List<X509Certificate> rootCaFromJdkTrustedCertificates = CertificateUtils.getRootCaFromJdkTrustedCertificates(x509Certificate);
        if (!rootCaFromJdkTrustedCertificates.isEmpty()) {
            return rootCaFromJdkTrustedCertificates;
        }

        return Collections.emptyList();
    }

    static List<X509Certificate> getRootCaFromAuthorityInfoAccessExtensionIfPresent(X509Certificate certificate) {
        if (!(certificate instanceof X509CertImpl)) {
            return Collections.emptyList();
        }

        X509CertImpl x509Certificate = (X509CertImpl) certificate;
        for (String rawExtensionId : x509Certificate.getNonCriticalExtensionOIDs()) {
            int[] extensionId = Arrays.stream(rawExtensionId.split("\\."))
                    .mapToInt(Integer::parseInt)
                    .toArray();

            Extension certificateExtension = x509Certificate.getExtension(ObjectIdentifier.newInternal(extensionId));

            if (certificateExtension instanceof AuthorityInfoAccessExtension) {
                AuthorityInfoAccessExtension authorityKeyIdentifierExtension = (AuthorityInfoAccessExtension) certificateExtension;
                List<AccessDescription> accessDescriptionsContainingUrlsToCertificates = authorityKeyIdentifierExtension.getAccessDescriptions().stream()
                        .filter(accessDescription -> accessDescription.getAccessMethod().toString().equals(CERTIFICATE_AUTHORITY_ISSUERS_ID))
                        .collect(Collectors.toList());

                return accessDescriptionsContainingUrlsToCertificates.stream()
                        .map(accessDescription -> accessDescription.getAccessLocation().getName())
                        .filter(URIName.class::isInstance)
                        .map(URIName.class::cast)
                        .map(URIName::getURI)
                        .map((URI uri) -> CertificateUtils.getCertificatesFromRemoteFile(uri, certificate))
                        .flatMap(Collection::stream)
                        .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
            }
        }
        return Collections.emptyList();
    }

    static List<X509Certificate> getCertificatesFromRemoteFile(URI uri, X509Certificate intermediateCertificate) {
        try (InputStream inputStream = uri.toURL().openStream();
             BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
             ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {

            byte[] dataBuffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = bufferedInputStream.read(dataBuffer, 0, 1024)) != -1) {
                byteArrayOutputStream.write(dataBuffer, 0, bytesRead);
            }

            CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            List<X509Certificate> certificates = certificateFactory.generateCertificates(byteArrayInputStream).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .filter(issuer -> CertificateUtils.isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                    .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));

            byteArrayInputStream.close();

            return certificates;
        } catch (IOException | CertificateException e) {
            throw new GenericCertificateException(e);
        }
    }

    static List<X509Certificate> getRootCaFromJdkTrustedCertificates(X509Certificate intermediateCertificate) {
        List<X509Certificate> jdkTrustedCertificates = CertificateUtils.getJdkTrustedCertificates();

        return jdkTrustedCertificates.stream()
                .filter(issuer -> isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    static boolean isIssuerOfIntermediateCertificate(X509Certificate intermediateCertificate, X509Certificate issuer) {
        try {
            intermediateCertificate.verify(issuer.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

    public static List<String> convertToPem(List<Certificate> certificates) {
        return certificates.stream()
                .map(CertificateUtils::convertToPem)
                .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    public static String convertToPem(Certificate certificate) {
        try {
            byte[] encodedCertificate = certificate.getEncoded();
            byte[] base64EncodedCertificate = Base64.getEncoder().encode(encodedCertificate);
            String parsedCertificate = new String(base64EncodedCertificate);

            List<String> certificateContainer = Stream.of(parsedCertificate.split("(?<=\\G.{64})"))
                    .collect(Collectors.toCollection(ArrayList::new));
            certificateContainer.add(0, CERTIFICATE_HEADER);
            certificateContainer.add(CERTIFICATE_FOOTER);

            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                X500Principal issuer = x509Certificate.getIssuerX500Principal();
                certificateContainer.add(0, String.format("issuer=%s", issuer.getName()));
                X500Principal subject = x509Certificate.getSubjectX500Principal();
                certificateContainer.add(0, String.format("subject=%s", subject.getName()));
            }

            return String.join(System.lineSeparator(), certificateContainer);
        } catch (CertificateEncodingException e) {
            throw new GenericCertificateException(e);
        }
    }

}
