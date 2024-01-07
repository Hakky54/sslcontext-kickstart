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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.internal.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
public class CertificateExtractingClient {

    private static final Pattern CA_ISSUERS_AUTHORITY_INFO_ACCESS = Pattern.compile("(?s)^AuthorityInfoAccess\\h+\\[\\R\\s*\\[\\R.*?accessMethod:\\h+caIssuers\\R\\h*accessLocation: URIName:\\h+(https?://\\S+)", Pattern.MULTILINE);

    private static CertificateExtractingClient instance;

    private final boolean shouldResolveRootCa;
    private final Proxy proxy;
    private final SSLFactory sslFactoryForCertificateCapturing;
    private final SSLFactory unsafeSslFactory;
    private final SSLSocketFactory unsafeSslSocketFactory;
    private final SSLSocketFactory certificateCapturingSslSocketFactory;
    private final List<X509Certificate> certificatesCollector;

    private CertificateExtractingClient(boolean shouldResolveRootCa, Proxy proxy, PasswordAuthentication passwordAuthentication) {
        this.shouldResolveRootCa = shouldResolveRootCa;
        this.proxy = proxy;

        if (passwordAuthentication != null) {
            Authenticator authenticator = new FelixAuthenticator(passwordAuthentication);
            Authenticator.setDefault(authenticator);
        }

        certificatesCollector = new CopyOnWriteArrayList<>();

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

    static CertificateExtractingClient getInstance() {
        if (instance == null) {
            instance = new CertificateExtractingClient(true, null, null);
        } else {
            instance.certificatesCollector.clear();
            SSLSessionUtils.invalidateCaches(instance.sslFactoryForCertificateCapturing);
        }
        return instance;
    }

    public List<X509Certificate> get(String url) {
        try {
            URL parsedUrl = new URL(url);
            if ("https".equalsIgnoreCase(parsedUrl.getProtocol())) {
                HttpsURLConnection connection = (HttpsURLConnection) createConnection(parsedUrl);
                connection.setSSLSocketFactory(certificateCapturingSslSocketFactory);
                connection.connect();
                connection.disconnect();

                if (shouldResolveRootCa) {
                    List<X509Certificate> resolvedRootCa = getRootCaFromChainIfPossible(certificatesCollector);
                    return Stream.of(certificatesCollector, resolvedRootCa)
                            .flatMap(Collection::stream)
                            .collect(toUnmodifiableList());
                }

                return Collections.unmodifiableList(certificatesCollector);
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

    private static class FelixAuthenticator extends Authenticator {

        private final PasswordAuthentication passwordAuthentication;

        private FelixAuthenticator(PasswordAuthentication passwordAuthentication) {
            this.passwordAuthentication = passwordAuthentication;
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            return passwordAuthentication;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Proxy proxy = null;
        private PasswordAuthentication passwordAuthentication = null;
        private boolean shouldResolveRootCa = true;

        public Builder withProxy(Proxy proxy) {
            this.proxy = proxy;
            return this;
        }

        public Builder withProxyPasswordAuthentication(PasswordAuthentication passwordAuthentication) {
            this.passwordAuthentication = passwordAuthentication;
            return this;
        }

        public Builder withResolvedRootCa(boolean shouldResolveRootCa) {
            this.shouldResolveRootCa = shouldResolveRootCa;
            return this;
        }

        public CertificateExtractingClient build() {
            return new CertificateExtractingClient(shouldResolveRootCa, proxy, passwordAuthentication);
        }

    }

}
