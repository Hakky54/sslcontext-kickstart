package nl.altindag.sslcontext.socket;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public final class CompositeSSLServerSocketFactory extends SSLServerSocketFactory {

    private final SSLServerSocketFactory sslServerSocketFactory;
    private final SSLParameters sslParameters;

    public CompositeSSLServerSocketFactory(SSLServerSocketFactory sslServerSocketFactory, SSLParameters sslParameters) {
        this.sslServerSocketFactory = sslServerSocketFactory;
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
    public ServerSocket createServerSocket() throws IOException {
        ServerSocket serverSocket = sslServerSocketFactory.createServerSocket();
        return withSslParameters(serverSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        ServerSocket serverSocket = sslServerSocketFactory.createServerSocket(port);
        return withSslParameters(serverSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        ServerSocket serverSocket = sslServerSocketFactory.createServerSocket(port, backlog);
        return withSslParameters(serverSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        ServerSocket serverSocket = sslServerSocketFactory.createServerSocket(port, backlog, ifAddress);
        return withSslParameters(serverSocket);
    }

    private ServerSocket withSslParameters(ServerSocket socket) {
        if (socket instanceof SSLServerSocket) {
            SSLServerSocket sslSocket = (SSLServerSocket) socket;
            sslSocket.setSSLParameters(sslParameters);
        }
        return socket;
    }

}
