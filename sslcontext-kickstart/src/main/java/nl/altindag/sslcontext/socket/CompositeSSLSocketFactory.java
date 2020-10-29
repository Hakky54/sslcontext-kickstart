package nl.altindag.sslcontext.socket;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public final class CompositeSSLSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory sslSocketFactory;
    private final SSLParameters sslParameters;

    public CompositeSSLSocketFactory(SSLSocketFactory sslSocketFactory, SSLParameters sslParameters) {
        this.sslSocketFactory = sslSocketFactory;
        this.sslParameters = sslParameters;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslParameters.getCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslParameters.getCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClosable) throws IOException {
        Socket newSocket = sslSocketFactory.createSocket(socket, host, port, autoClosable);
        return withSslParameters(newSocket);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        Socket socket = sslSocketFactory.createSocket(host, port);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException, UnknownHostException {
        Socket socket = sslSocketFactory.createSocket(host, port, localAddress, localPort);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        Socket socket = sslSocketFactory.createSocket(address, port);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = sslSocketFactory.createSocket(address, port, localAddress, localPort);
        return withSslParameters(socket);
    }

    private Socket withSslParameters(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.setSSLParameters(sslParameters);
        }
        return socket;
    }

}
