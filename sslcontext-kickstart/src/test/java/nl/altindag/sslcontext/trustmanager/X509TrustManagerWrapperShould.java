package nl.altindag.sslcontext.trustmanager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509TrustManagerWrapperShould {

    @Test
    void checkClientTrusted() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkClientTrusted(null, null);

        verify(trustManager, times(1)).checkClientTrusted(null, null);
    }

    @Test
    void checkClientTrustedWithSocket() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkClientTrusted(null, null, (Socket) null);

        verify(trustManager, times(1)).checkClientTrusted(null, null);
    }

    @Test
    void checkClientTrustedWithSslEngine() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkClientTrusted(null, null, (SSLEngine) null);

        verify(trustManager, times(1)).checkClientTrusted(null, null);
    }

    @Test
    void checkServerTrusted() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkServerTrusted(null, null);

        verify(trustManager, times(1)).checkServerTrusted(null, null);
    }

    @Test
    void checkServerTrustedWithSocket() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkServerTrusted(null, null, (Socket) null);

        verify(trustManager, times(1)).checkServerTrusted(null, null);
    }

    @Test
    void checkServerTrustedWithSslEngine() throws CertificateException {
        X509TrustManager trustManager = mock(X509TrustManager.class);

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        victim.checkServerTrusted(null, null, (SSLEngine) null);

        verify(trustManager, times(1)).checkServerTrusted(null, null);
    }

    @Test
    void getAcceptedIssuers() {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        when(trustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{mock(X509Certificate.class)});

        X509TrustManagerWrapper victim = new X509TrustManagerWrapper(trustManager);
        X509Certificate[] acceptedIssuers = victim.getAcceptedIssuers();

        assertThat(acceptedIssuers).hasSize(1);
        verify(trustManager, times(1)).getAcceptedIssuers();
    }

    @Test
    void throwNullPointerExceptionWhenKeyManagerIsNotPresent() {
        assertThatThrownBy(() -> new X509TrustManagerWrapper(null))
                .isInstanceOf(NullPointerException.class);
    }

}
