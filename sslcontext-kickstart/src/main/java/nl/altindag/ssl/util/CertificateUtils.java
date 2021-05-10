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

import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

import javax.net.ssl.HttpsURLConnection;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
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

        return certificates;
    }

    public static List<Certificate> getSystemTrustedCertificates() {
        try {
            List<Certificate> certificates = new ArrayList<>();
            for (KeyStore keyStore : KeyStoreUtils.loadSystemKeyStores()) {
                for (String alias : Collections.list(keyStore.aliases())) {
                    if (keyStore.isCertificateEntry(alias)) {
                        Certificate certificate = keyStore.getCertificate(alias);
                        certificates.add(certificate);
                    }
                }
            }
            return certificates;
        } catch (KeyStoreException e) {
            throw new GenericCertificateException(e);
        }
    }

    public static Map<String, List<String>> getCertificateAsPem(String... urls) {
        return getCertificateAsPem(Arrays.asList(urls));
    }

    public static Map<String, List<String>> getCertificateAsPem(List<String> urls) {
        return getCertificate(urls).entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> CertificateUtils.convertToPem(entry.getValue())));
    }

    public static Map<String, List<Certificate>> getCertificate(String... urls) {
        return getCertificate(Arrays.asList(urls));
    }

    public static Map<String, List<Certificate>> getCertificate(List<String> urls) {
        Map<String, List<Certificate>> certificates = new HashMap<>();
        for (String url : urls) {
            List<Certificate> serverCertificates = getCertificateFromExternalSource(url);
            certificates.put(url, serverCertificates);
        }
        return certificates;
    }

    private static List<Certificate> getCertificateFromExternalSource(String url) {
        try {
            URL parsedUrl = new URL(url);
            if ("https".equalsIgnoreCase(parsedUrl.getProtocol())) {
                HttpsURLConnection connection = (HttpsURLConnection) parsedUrl.openConnection();
                connection.connect();

                Certificate[] serverCertificates = connection.getServerCertificates();
                ArrayList<Certificate> certificates = new ArrayList<>(Arrays.asList(serverCertificates));

                if (serverCertificates.length > 1) {
                    Certificate certificate = serverCertificates[serverCertificates.length - 1];
                    if (certificate instanceof X509CertImpl) {
                        List<Certificate> rootCertificates = bla((X509CertImpl) certificate);
                        certificates.addAll(rootCertificates);
                    }
                }

                connection.disconnect();
                return certificates.stream()
                        .distinct()
                        .collect(Collectors.toList());
            } else {
                return Collections.emptyList();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<Certificate> bla(X509CertImpl certificate) throws IOException {
        for (String extOID : certificate.getNonCriticalExtensionOIDs()) {
            Extension certExtension = certificate.getExtension(new ObjectIdentifier(extOID));

            if (certExtension instanceof AuthorityInfoAccessExtension) {
                AuthorityInfoAccessExtension authorityKeyIdentifierExtension = (AuthorityInfoAccessExtension) certExtension;
                List<AccessDescription> accessDescriptionsContainingUrlsToCertificates = authorityKeyIdentifierExtension.getAccessDescriptions().stream()
                        .filter(accessDescription -> accessDescription.getAccessMethod().toString().equals("1.3.6.1.5.5.7.48.2"))
                        .collect(Collectors.toList());

                return accessDescriptionsContainingUrlsToCertificates.stream()
                        .map(accessDescription -> accessDescription.getAccessLocation().getName())
                        .filter(accessLocationName -> accessLocationName instanceof URIName)
                        .map(URIName.class::cast)
                        .map(URIName::getURI)
                        .map(CertificateUtils::getCertificatesFromRemoteFile)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toList());
            }
        }

        return Collections.emptyList();
    }

    private static List<Certificate> getCertificatesFromRemoteFile(URI uri) {
        try (BufferedInputStream in = new BufferedInputStream(uri.toURL().openStream());
             ByteArrayOutputStream fileOutputStream = new ByteArrayOutputStream()) {

            byte[] dataBuffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                fileOutputStream.write(dataBuffer, 0, bytesRead);
            }

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(fileOutputStream.toByteArray()));

            return new ArrayList<>(certificates);
        } catch (IOException | CertificateException e) {
            throw new RuntimeException();
        }
    }

    public static List<String> convertToPem(List<Certificate> certificates) {
        return certificates.stream()
                .map(CertificateUtils::convertToPem)
                .collect(Collectors.toList());
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
