/*
 * Copyright 2019 Thunderberry.
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
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
class CertificateExtractorUtils {

    private static final Pattern CA_ISSUERS_AUTHORITY_INFO_ACCESS = Pattern.compile("(?s)^AuthorityInfoAccess\\h+\\[\\R\\s*\\[\\R.*?accessMethod:\\h+caIssuers\\R\\h*accessLocation: URIName:\\h+(https?://\\S+)", Pattern.MULTILINE);

    private static CertificateExtractorUtils instance;

    private final SSLFactory sslFactoryForCertificateCapturing;
    private final SSLFactory unsafeSslFactory;
    private final SSLSocketFactory unsafeSslSocketFactory;
    private final SSLSocketFactory certificateCapturingSslSocketFactory;
    private final List<X509Certificate> certificatesCollector;

    private Proxy proxy;

    private CertificateExtractorUtils() {
        certificatesCollector = new ArrayList<>();

        X509ExtendedTrustManager certificateCapturingTrustManager = TrustManagerUtils.createCertificateCapturingTrustManager(certificatesCollector);

        sslFactoryForCertificateCapturing = SSLFactory.builder()
                .withTrustMaterial(certificateCapturingTrustManager)
                .build();

        unsafeSslFactory = SSLFactory.builder()
                .withUnsafeTrustMaterial()
                .build();

        certificateCapturingSslSocketFactory = sslFactoryForCertificateCapturing.getSslSocketFactory();
        unsafeSslSocketFactory = unsafeSslFactory.getSslSocketFactory();
    }

    protected CertificateExtractorUtils(Proxy proxy) {
        this();
        this.proxy = proxy;
    }

    protected CertificateExtractorUtils(Proxy proxy, PasswordAuthentication passwordAuthentication) {
        this(proxy);

        Authenticator authenticator = new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return passwordAuthentication;
            }
        };

        Authenticator.setDefault(authenticator);
    }

    static CertificateExtractorUtils getInstance() {
        if (instance == null) {
            instance = new CertificateExtractorUtils();
        } else {
            instance.certificatesCollector.clear();
            SSLSessionUtils.invalidateCaches(instance.sslFactoryForCertificateCapturing);
        }
        return instance;
    }

    List<X509Certificate> getCertificateFromExternalSource(String url) {
        try {
            URL parsedUrl = new URL(url);
            if ("https".equalsIgnoreCase(parsedUrl.getProtocol())) {
                HttpsURLConnection connection = (HttpsURLConnection) createConnection(parsedUrl);
                connection.setSSLSocketFactory(certificateCapturingSslSocketFactory);
                connection.connect();
                connection.disconnect();

                List<X509Certificate> rootCa = getRootCaFromChainIfPossible(certificatesCollector);
                return Stream.of(certificatesCollector, rootCa)
                        .flatMap(Collection::stream)
                        .distinct()
                        .collect(toUnmodifiableList());
            } else {
                return Collections.emptyList();
            }
        } catch (IOException e) {
            throw new GenericIOException(String.format("Failed getting certificate from: [%s]", url), e);
        } finally {
            SSLSessionUtils.invalidateCaches(sslFactoryForCertificateCapturing);
        }
    }

    private URLConnection createConnection(URL url) throws IOException {
        return proxy != null ? url.openConnection(proxy) : url.openConnection();
    }

    List<X509Certificate> getRootCaFromChainIfPossible(List<X509Certificate> certificates) {
        if (!certificates.isEmpty()) {
            X509Certificate certificate = certificates.get(certificates.size() - 1);
            String issuer = certificate.getIssuerX500Principal().getName();
            String subject = certificate.getSubjectX500Principal().getName();

            boolean isSelfSignedCertificate = issuer.equals(subject);
            if (!isSelfSignedCertificate) {
                return getRootCaIfPossible(certificate);
            }
        }
        return Collections.emptyList();
    }

    List<X509Certificate> getRootCaIfPossible(X509Certificate x509Certificate) {
        List<X509Certificate> rootCaFromAuthorityInfoAccessExtension = getRootCaFromAuthorityInfoAccessExtensionIfPresent(x509Certificate);
        if (!rootCaFromAuthorityInfoAccessExtension.isEmpty()) {
            return rootCaFromAuthorityInfoAccessExtension;
        }

        List<X509Certificate> rootCaFromJdkTrustedCertificates = getRootCaFromJdkTrustedCertificates(x509Certificate);
        if (!rootCaFromJdkTrustedCertificates.isEmpty()) {
            return rootCaFromJdkTrustedCertificates;
        }

        return Collections.emptyList();
    }

    List<X509Certificate> getRootCaFromAuthorityInfoAccessExtensionIfPresent(X509Certificate certificate) {
        String certificateContent = certificate.toString();
        Matcher caIssuersMatcher = CA_ISSUERS_AUTHORITY_INFO_ACCESS.matcher(certificateContent);
        if (caIssuersMatcher.find()) {
            String issuerLocation = caIssuersMatcher.group(1);
            return getCertificatesFromRemoteFile(URI.create(issuerLocation), certificate);
        }

        return Collections.emptyList();
    }

    List<X509Certificate> getCertificatesFromRemoteFile(URI uri, X509Certificate intermediateCertificate) {
        try {
            URL url = uri.toURL();
            URLConnection connection = createConnection(url);
            if (connection instanceof HttpsURLConnection) {
                ((HttpsURLConnection) connection).setSSLSocketFactory(unsafeSslSocketFactory);
            }

            InputStream inputStream = connection.getInputStream();
            List<X509Certificate> certificates = CertificateUtils.parseDerCertificate(inputStream).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .filter(issuer -> isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                    .collect(toUnmodifiableList());

            inputStream.close();

            return certificates;
        } catch (IOException e) {
            throw new GenericCertificateException(e);
        } finally {
            SSLSessionUtils.invalidateCaches(unsafeSslFactory);
        }
    }

    List<X509Certificate> getRootCaFromJdkTrustedCertificates(X509Certificate intermediateCertificate) {
        List<X509Certificate> jdkTrustedCertificates = CertificateUtils.getJdkTrustedCertificates();

        return jdkTrustedCertificates.stream()
                .filter(issuer -> isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                .collect(toUnmodifiableList());
    }

    boolean isIssuerOfIntermediateCertificate(X509Certificate intermediateCertificate, X509Certificate issuer) {
        try {
            intermediateCertificate.verify(issuer.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

}
