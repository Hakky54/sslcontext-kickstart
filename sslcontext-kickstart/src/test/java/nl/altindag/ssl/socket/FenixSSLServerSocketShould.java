package nl.altindag.ssl.socket;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SuppressWarnings("ResultOfMethodCallIgnored")
class FenixSSLServerSocketShould {

    private SSLServerSocket socket;
    private SSLServerSocket wrapperSocket;
    private SSLParameters sslParameters;
    private static LogCaptor logCaptor;

    @BeforeAll
    static void setupLogCaptor() {
        logCaptor = LogCaptor.forClass(FenixSSLServerSocket.class);
    }

    @AfterAll
    static void closeLogCaptor() {
        logCaptor.close();
    }

    @BeforeEach
    void setup() throws IOException {
        socket = mock(SSLServerSocket.class);
        sslParameters = new SSLParameters();
        wrapperSocket = new FenixSSLServerSocket(socket, sslParameters);
    }

    @AfterEach
    void clearLogs() {
        logCaptor.clearLogs();
    }

    @Test
    void setSSLParameters() {
        wrapperSocket.setSSLParameters(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ssl parameters");
    }

    @Test
    void setEnabledCipherSuites() {
        wrapperSocket.setEnabledCipherSuites(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ciphers");
    }

    @Test
    void setEnabledProtocols() {
        wrapperSocket.setEnabledProtocols(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided protocols");
    }

    @Test
    void setNeedClientAuth() {
        wrapperSocket.setNeedClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for need client auth");
    }

    @Test
    void setWantClientAuth() {
        wrapperSocket.setWantClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for want client auth");
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSocket.getEnabledCipherSuites();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getEnabledCipherSuites();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSocket.getEnabledProtocols();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getEnabledProtocols();
    }

    @Test
    void getNeedClientAuth() {
        wrapperSocket.getNeedClientAuth();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getNeedClientAuth();
    }

    @Test
    void getWantClientAuth() {
        wrapperSocket.getWantClientAuth();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getWantClientAuth();
    }

    @Test
    void getSSLParameters() {
        wrapperSocket.getSSLParameters();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getSSLParameters();
    }

}
