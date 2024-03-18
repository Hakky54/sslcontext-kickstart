package nl.altindag.ssl.socket;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SuppressWarnings("ResultOfMethodCallIgnored")
class DelegatingSSLSocketShould {

    private SSLSocket socket;
    private SSLSocket wrapperSocket;

    @BeforeEach
    void setup() {
        socket = mock(SSLSocket.class);
        wrapperSocket = new DelegatingSSLSocket(socket);
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSocket.getEnabledCipherSuites();
        verify(socket, times(1)).getEnabledCipherSuites();
    }

    @Test
    void setEnabledCipherSuites() {
        String[] ciphers = {"some-cipher"};
        wrapperSocket.setEnabledCipherSuites(ciphers);
        verify(socket, times(1)).setEnabledCipherSuites(ciphers);
    }

    @Test
    void getSupportedCipherSuites() {
        wrapperSocket.getSupportedCipherSuites();
        verify(socket, times(1)).getSupportedCipherSuites();
    }

    @Test
    void getSupportedProtocols() {
        wrapperSocket.getSupportedProtocols();
        verify(socket, times(1)).getSupportedProtocols();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSocket.getEnabledProtocols();
        verify(socket, times(1)).getEnabledProtocols();
    }

    @Test
    void setEnabledProtocols() {
        String[] protocols = {"some-protocols"};
        wrapperSocket.setEnabledProtocols(protocols);
        verify(socket, times(1)).setEnabledProtocols(protocols);
    }

    @Test
    void setNeedClientAuth() {
        wrapperSocket.setNeedClientAuth(true);
        verify(socket, times(1)).setNeedClientAuth(true);
    }

    @Test
    void getNeedClientAuth() {
        wrapperSocket.getNeedClientAuth();
        verify(socket, times(1)).getNeedClientAuth();
    }

    @Test
    void setWantClientAuth() {
        wrapperSocket.setWantClientAuth(true);
        verify(socket, times(1)).setWantClientAuth(true);
    }

    @Test
    void getWantClientAuth() {
        wrapperSocket.getWantClientAuth();
        verify(socket, times(1)).getWantClientAuth();
    }

    @Test
    void setUseClientMode() {
        wrapperSocket.setUseClientMode(true);
        verify(socket, times(1)).setUseClientMode(true);
    }

    @Test
    void getUseClientMode() {
        wrapperSocket.getUseClientMode();
        verify(socket, times(1)).getUseClientMode();
    }

    @Test
    void setEnableSessionCreation() {
        wrapperSocket.setEnableSessionCreation(true);
        verify(socket, times(1)).setEnableSessionCreation(true);
    }

    @Test
    void getEnableSessionCreation() {
        wrapperSocket.getEnableSessionCreation();
        verify(socket, times(1)).getEnableSessionCreation();
    }

    @Test
    void getSSLParameters() {
        wrapperSocket.getSSLParameters();
        verify(socket, times(1)).getSSLParameters();
    }

    @Test
    void setSSLParameters() {
        SSLParameters sslParameters = mock(SSLParameters.class);
        wrapperSocket.setSSLParameters(sslParameters);
        verify(socket, times(1)).setSSLParameters(sslParameters);
    }

    @Test
    void bind() throws IOException {
        SocketAddress socketAddress = mock(SocketAddress.class);
        wrapperSocket.bind(socketAddress);
        verify(socket, times(1)).bind(socketAddress);
    }

    @Test
    void getInetAddress() {
        wrapperSocket.getInetAddress();
        verify(socket, times(1)).getInetAddress();
    }

    @Test
    void getLocalPort() {
        wrapperSocket.getLocalPort();
        verify(socket, times(1)).getLocalPort();
    }

    @Test
    void getLocalSocketAddress() {
        wrapperSocket.getLocalSocketAddress();
        verify(socket, times(1)).getLocalSocketAddress();
    }

    @Test
    void close() throws IOException {
        wrapperSocket.close();
        verify(socket, times(1)).close();
    }

    @Test
    void getChannel() {
        wrapperSocket.getChannel();
        verify(socket, times(1)).getChannel();
    }

    @Test
    void isBound() {
        wrapperSocket.isBound();
        verify(socket, times(1)).isBound();
    }

    @Test
    void isClosed() {
        wrapperSocket.isClosed();
        verify(socket, times(1)).isClosed();
    }

    @Test
    void setSoTimeout() throws SocketException {
        wrapperSocket.setSoTimeout(100);
        verify(socket, times(1)).setSoTimeout(100);
    }

    @Test
    void getSoTimeout() throws IOException {
        wrapperSocket.getSoTimeout();
        verify(socket, times(1)).getSoTimeout();
    }

    @Test
    void setReuseAddress() throws SocketException {
        wrapperSocket.setReuseAddress(true);
        verify(socket, times(1)).setReuseAddress(true);
    }

    @Test
    void getReuseAddress() throws SocketException {
        wrapperSocket.getReuseAddress();
        verify(socket, times(1)).getReuseAddress();
    }

    @Test
    void callDelegateToString() {
        when(socket.toString()).thenReturn("hello");
        String result = wrapperSocket.toString();

        assertThat(result).isEqualTo("hello");
    }

    @Test
    void setReceiveBufferSize() throws SocketException {
        wrapperSocket.setReceiveBufferSize(1000);
        verify(socket, times(1)).setReceiveBufferSize(1000);
    }

    @Test
    void getReceiveBufferSize() throws SocketException {
        wrapperSocket.getReceiveBufferSize();
        verify(socket, times(1)).getReceiveBufferSize();
    }

    @Test
    void setPerformancePreferences() throws SocketException {
        wrapperSocket.setPerformancePreferences(1000, 1000, 1000);
        verify(socket, times(1)).setPerformancePreferences(1000, 1000, 1000);
    }

    @Test
    void getSession() {
        wrapperSocket.getSession();
        verify(socket, times(1)).getSession();
    }

    @Test
    void addHandshakeCompletedListener() {
        HandshakeCompletedListener listener = mock(HandshakeCompletedListener.class);
        wrapperSocket.addHandshakeCompletedListener(listener);
        verify(socket, times(1)).addHandshakeCompletedListener(listener);
    }

    @Test
    void removeHandshakeCompletedListener() {
        HandshakeCompletedListener listener = mock(HandshakeCompletedListener.class);
        wrapperSocket.removeHandshakeCompletedListener(listener);
        verify(socket, times(1)).removeHandshakeCompletedListener(listener);
    }

    @Test
    void startHandshake() throws IOException {
        wrapperSocket.startHandshake();
        verify(socket, times(1)).startHandshake();
    }

    @Test
    void getHandshakeSession() {
        wrapperSocket.getHandshakeSession();
        verify(socket, times(1)).getHandshakeSession();
    }

    @Test
    void connect() throws IOException {
        SocketAddress address = mock(SocketAddress.class);
        wrapperSocket.connect(address);
        verify(socket, times(1)).connect(address);
    }

    @Test
    void connectWithTimeout() throws IOException {
        SocketAddress address = mock(SocketAddress.class);
        wrapperSocket.connect(address, 100);
        verify(socket, times(1)).connect(address, 100);
    }

    @Test
    void getLocalAddress() {
        wrapperSocket.getLocalAddress();
        verify(socket, times(1)).getLocalAddress();
    }

    @Test
    void getPort() {
        wrapperSocket.getPort();
        verify(socket, times(1)).getPort();
    }

    @Test
    void getRemoteSocketAddress() {
        wrapperSocket.getRemoteSocketAddress();
        verify(socket, times(1)).getRemoteSocketAddress();
    }

    @Test
    void getInputStream() throws IOException {
        wrapperSocket.getInputStream();
        verify(socket, times(1)).getInputStream();
    }

    @Test
    void getOutputStream() throws IOException {
        wrapperSocket.getOutputStream();
        verify(socket, times(1)).getOutputStream();
    }

    @Test
    void setTcpNoDelay() throws SocketException {
        wrapperSocket.setTcpNoDelay(true);
        verify(socket, times(1)).setTcpNoDelay(true);
    }

    @Test
    void getTcpNoDelay() throws SocketException {
        wrapperSocket.getTcpNoDelay();
        verify(socket, times(1)).getTcpNoDelay();
    }

    @Test
    void setSoLinger() throws SocketException {
        wrapperSocket.setSoLinger(true, 100);
        verify(socket, times(1)).setSoLinger(true, 100);
    }

    @Test
    void getSoLinger() throws SocketException {
        wrapperSocket.getSoLinger();
        verify(socket, times(1)).getSoLinger();
    }

    @Test
    void sendUrgentData() throws IOException {
        wrapperSocket.sendUrgentData(100);
        verify(socket, times(1)).sendUrgentData(100);
    }

    @Test
    void setOOBInline() throws SocketException {
        wrapperSocket.setOOBInline(true);
        verify(socket, times(1)).setOOBInline(true);
    }

    @Test
    void getOOBInline() throws SocketException {
        wrapperSocket.getOOBInline();
        verify(socket, times(1)).getOOBInline();
    }

    @Test
    void setSendBufferSize() throws SocketException {
        wrapperSocket.setSendBufferSize(100);
        verify(socket, times(1)).setSendBufferSize(100);
    }

    @Test
    void getSendBufferSize() throws SocketException {
        wrapperSocket.getSendBufferSize();
        verify(socket, times(1)).getSendBufferSize();
    }

    @Test
    void setKeepAlive() throws SocketException {
        wrapperSocket.setKeepAlive(true);
        verify(socket, times(1)).setKeepAlive(true);
    }

    @Test
    void getKeepAlive() throws SocketException {
        wrapperSocket.getKeepAlive();
        verify(socket, times(1)).getKeepAlive();
    }

    @Test
    void setTrafficClass() throws SocketException {
        wrapperSocket.setTrafficClass(100);
        verify(socket, times(1)).setTrafficClass(100);
    }

    @Test
    void getTrafficClass() throws SocketException {
        wrapperSocket.getTrafficClass();
        verify(socket, times(1)).getTrafficClass();
    }

    @Test
    void shutdownInput() throws IOException {
        wrapperSocket.shutdownInput();
        verify(socket, times(1)).shutdownInput();
    }

    @Test
    void shutdownOutput() throws IOException {
        wrapperSocket.shutdownOutput();
        verify(socket, times(1)).shutdownOutput();
    }

    @Test
    void isConnected() {
        wrapperSocket.isConnected();
        verify(socket, times(1)).isConnected();
    }

    @Test
    void isInputShutdown() {
        wrapperSocket.isInputShutdown();
        verify(socket, times(1)).isInputShutdown();
    }

    @Test
    void isOutputShutdown() {
        wrapperSocket.isOutputShutdown();
        verify(socket, times(1)).isOutputShutdown();
    }

}
