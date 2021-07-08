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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Hakan Altindag
 */
public final class CertificateUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String P7B_HEADER = "-----BEGIN PKCS7-----";
    private static final String P7B_FOOTER = "-----END PKCS7-----";
    private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(PEM_HEADER + "(.*?)" + PEM_FOOTER, Pattern.DOTALL);
    private static final Pattern P7B_PATTERN = Pattern.compile(P7B_HEADER + "(.*?)" + P7B_FOOTER, Pattern.DOTALL);

    private static final String EMPTY = "";
    private static final Pattern CA_ISSUERS_AUTHORITY_INFO_ACCESS = Pattern.compile("(?s)^AuthorityInfoAccess\\h+\\[\\R\\s*\\[\\R.*?accessMethod:\\h+caIssuers\\R\\h*accessLocation: URIName:\\h+(https?://\\S+)", Pattern.MULTILINE);

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

    /**
     * Loads certificates from the classpath and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    public static List<Certificate> loadCertificate(String... certificatePaths) {
        return loadCertificate(certificatePath -> CertificateUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    /**
     * Loads certificates from the filesystem and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    public static List<Certificate> loadCertificate(Path... certificatePaths) {
        return loadCertificate(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new GenericIOException(exception);
            }
        }, certificatePaths);
    }

    /**
     * Loads certificates from multiple InputStreams and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
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

    /**
     * Tries to map the InputStream to a list of {@link Certificate}.
     * It assumes that the content of the InputStream is either PEM, P7B or DER.
     * The InputStream will copied into an OutputStream so it can be read multiple times.
     */
    private static List<Certificate> parseCertificate(InputStream certificateStream) {
        List<Certificate> certificates;
        List<InputStream> toBeClosedStreams = new ArrayList<>();
        ByteArrayOutputStream duplicatedCertificateStream = IOUtils.createCopy(certificateStream);

        Function<byte[], InputStream> inputStreamMapper = bytes -> {
            InputStream inputStream = new ByteArrayInputStream(bytes);
            toBeClosedStreams.add(inputStream);
            return inputStream;
        };

        Supplier<InputStream> certificateSupplier = () -> inputStreamMapper.apply(duplicatedCertificateStream.toByteArray());

        if (isPemFormatted(certificateSupplier.get())) {
            String certificateContent = IOUtils.getContent(certificateSupplier.get());
            certificates = parsePemCertificate(certificateContent);
        } else if(isP7bFormatted(certificateSupplier.get())) {
            String certificateContent = IOUtils.getContent(certificateSupplier.get());
            certificates = parseP7bCertificate(certificateContent);
        } else {
            certificates = parseDerCertificate(certificateSupplier.get());
        }

        toBeClosedStreams.forEach(IOUtils::closeSilently);
        IOUtils.closeSilently(duplicatedCertificateStream);
        return certificates;
    }

    private static boolean isPemFormatted(InputStream certificateStream) {
        String content = IOUtils.getContent(certificateStream);
        Matcher certificateMatcher = PEM_PATTERN.matcher(content);
        return certificateMatcher.find();
    }

    private static boolean isP7bFormatted(InputStream certificateStream) {
        String content = IOUtils.getContent(certificateStream);
        Matcher certificateMatcher = P7B_PATTERN.matcher(content);
        return certificateMatcher.find();
    }

    /**
     * Parses PEM formatted certificates containing a
     * header as -----BEGIN CERTIFICATE----- and footer as -----END CERTIFICATE-----
     * or header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    @Deprecated
    public static List<Certificate> parseCertificate(String certificateContent) {
        return parsePemCertificate(certificateContent);
    }

    /**
     * Parses PEM formatted certificates containing a
     * header as -----BEGIN CERTIFICATE----- and footer as -----END CERTIFICATE-----
     * or header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    public static List<Certificate> parsePemCertificate(String certificateContent) {
        Matcher pemMatcher = PEM_PATTERN.matcher(certificateContent);
        return parseCertificate(pemMatcher);
    }

    /**
     * Parses P7B formatted certificates containing a
     * header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    public static List<Certificate> parseP7bCertificate(String certificateContent) {
        Matcher p7bMatcher = P7B_PATTERN.matcher(certificateContent);
        return parseCertificate(p7bMatcher);
    }

    private static List<Certificate> parseCertificate(Matcher certificateMatcher) {
        List<Certificate> certificates = new ArrayList<>();
        while (certificateMatcher.find()) {
            String sanitizedCertificate = certificateMatcher.group(1).replace(System.lineSeparator(), EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate);
            List<Certificate> parsedCertificates = CertificateUtils.parseDerCertificate(certificateAsInputStream);
            certificates.addAll(parsedCertificates);
            IOUtils.closeSilently(certificateAsInputStream);
        }

        return Collections.unmodifiableList(certificates);
    }

    public static List<Certificate> parseDerCertificate(InputStream certificateStream) {
        try(BufferedInputStream bufferedCertificateStream = new BufferedInputStream(certificateStream)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
            return certificateFactory.generateCertificates(bufferedCertificateStream).stream()
                    .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
        } catch (CertificateException | IOException e) {
            throw new GenericCertificateException("There is no valid certificate present to parse. Please make sure to supply a valid der formatted certificate", e);
        }
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
            throw new GenericIOException(e);
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
        String certificateContent = certificate.toString();
        Matcher caIssuersMatcher = CA_ISSUERS_AUTHORITY_INFO_ACCESS.matcher(certificateContent);
        if (caIssuersMatcher.find()) {
            String issuerLocation = caIssuersMatcher.group(1);
            return CertificateUtils.getCertificatesFromRemoteFile(URI.create(issuerLocation), certificate);
        }

        return Collections.emptyList();
    }

    static List<X509Certificate> getCertificatesFromRemoteFile(URI uri, X509Certificate intermediateCertificate) {
        try {
            URL url = uri.toURL();
            URLConnection connection = url.openConnection();
            if (connection instanceof HttpsURLConnection) {
                ((HttpsURLConnection) connection).setSSLSocketFactory(CertificateUtils.getUnsafeSslSocketFactory());
            }

            InputStream inputStream = connection.getInputStream();
            List<X509Certificate> certificates = CertificateUtils.parseDerCertificate(inputStream).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .filter(issuer -> CertificateUtils.isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                    .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));

            inputStream.close();

            return certificates;
        } catch (IOException e) {
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
            certificateContainer.add(0, PEM_HEADER);
            certificateContainer.add(PEM_FOOTER);

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
