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

import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class CertificateExtractorUtilsShould {

    @Test
    void getRootCaIfPossibleReturnsJdkTrustedCaCertificateWhenNoAuthorityInfoAccessExtensionIsPresent() {
        List<X509Certificate> certificates = CertificateUtils.getCertificate("https://www.reddit.com/")
                .get("https://www.reddit.com/");

        try (MockedStatic<CertificateExtractorUtils> mockedStatic = mockStatic(CertificateExtractorUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName())) {
                return Collections.emptyList();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            CertificateExtractorUtils victim = spy(CertificateExtractorUtils.getInstance());

            X509Certificate certificate = certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = victim.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isNotEmpty();

            verify(victim, times(1)).getRootCaFromJdkTrustedCertificates(certificate);
        }
    }

    @Test
    void getRootCaIfPossibleReturnsEmptyListWhenNoAuthorityInfoAccessExtensionIsPresentAndNoMatching() {
        List<X509Certificate> certificates = CertificateUtils.getCertificate("https://www.reddit.com/")
                .get("https://www.reddit.com/");

        try (MockedStatic<CertificateExtractorUtils> mockedStatic = mockStatic(CertificateExtractorUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName()) || "getRootCaFromJdkTrustedCertificates".equals(method.getName())) {
                return Collections.emptyList();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            CertificateExtractorUtils victim = spy(CertificateExtractorUtils.getInstance());

            doReturn(Collections.emptyList())
                    .when(victim)
                    .getRootCaFromJdkTrustedCertificates(any(X509Certificate.class));

            X509Certificate certificate = certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = victim.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isEmpty();

            verify(victim, times(1)).getRootCaFromAuthorityInfoAccessExtensionIfPresent(certificate);
            verify(victim, times(1)).getRootCaFromJdkTrustedCertificates(certificate);
        }
    }

    @Test
    void getRootCaFromChainIfPossibleReturnsEmptyListWhenNoCertificatesHaveBeenProvided() {
        List<X509Certificate> rootCa = CertificateExtractorUtils.getInstance().getRootCaFromChainIfPossible(Collections.emptyList());
        assertThat(rootCa).isEmpty();
    }

    @Test
    void getRootCaFromAuthorityInfoAccessExtensionIfPresentReturnsEmptyListWhenCertificateIsNotInstanceOfX509CertImpl() {
        List<X509Certificate> rootCa = CertificateExtractorUtils.getInstance().getRootCaFromAuthorityInfoAccessExtensionIfPresent(mock(X509Certificate.class));
        assertThat(rootCa).isEmpty();
    }

    @Test
    void throwsGenericCertificateExceptionWhenGetCertificatesFromRemoteFileFails() throws MalformedURLException {
        CertificateExtractorUtils victim = CertificateExtractorUtils.getInstance();

        URI uri = mock(URI.class);
        doThrow(new MalformedURLException("KABOOM!!!"))
                .when(uri).toURL();

        assertThatThrownBy(() -> victim.getCertificatesFromRemoteFile(uri, null))
                .isInstanceOf(GenericCertificateException.class)
                .hasMessageContaining("KABOOM!!!");
    }

    @Test
    void reUseExistingUnsafeSslSocketFactory() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        URI uri = URI.create("https://cacerts.digicert.com/DigiCertGlobalRootCA.crt");
        X509Certificate intermediateCertificate = mock(X509Certificate.class);
        doNothing().when(intermediateCertificate).verify(any());

        List<X509Certificate> certificatesFromRemoteFile = CertificateExtractorUtils.getInstance().getCertificatesFromRemoteFile(uri, intermediateCertificate);
        assertThat(certificatesFromRemoteFile).isNotEmpty();
    }

    @Test
    void extractCertificatesWithProxyAndAuthentication() {
        CertificateExtractorUtils certificateExtractorUtilsWithoutProxy = CertificateExtractorUtils.getInstance();
        List<X509Certificate> certificates = certificateExtractorUtilsWithoutProxy.getCertificateFromExternalSource("https://google.com");
        assertThat(certificates).isNotEmpty();

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("my-custom-host", 8081));
        CertificateExtractorUtils certificateExtractorUtilsWithProxy = new CertificateExtractorUtils(proxy);

        assertThatThrownBy(() -> certificateExtractorUtilsWithProxy.getCertificateFromExternalSource("https://google.com"))
                .isInstanceOf(GenericIOException.class)
                .hasMessage("Failed getting certificate from: [https://google.com]")
                .hasRootCauseInstanceOf(UnknownHostException.class)
                .hasRootCauseMessage("my-custom-host");

        try (MockedStatic<Authenticator> mockedAuthenticator = mockStatic(Authenticator.class, InvocationOnMock::callRealMethod)) {
            PasswordAuthentication passwordAuthentication = new PasswordAuthentication("foo", "bar".toCharArray());
            CertificateExtractorUtils certificateExtractorUtilsWithProxyAndAuthentication = new CertificateExtractorUtils(proxy, passwordAuthentication);

            assertThatThrownBy(() -> certificateExtractorUtilsWithProxyAndAuthentication.getCertificateFromExternalSource("https://google.com"))
                    .isInstanceOf(GenericIOException.class)
                    .hasMessage("Failed getting certificate from: [https://google.com]")
                    .hasRootCauseInstanceOf(UnknownHostException.class)
                    .hasRootCauseMessage("my-custom-host");

            mockedAuthenticator.verify(() -> Authenticator.setDefault(any(Authenticator.class)), times(1));
        }
    }

}
