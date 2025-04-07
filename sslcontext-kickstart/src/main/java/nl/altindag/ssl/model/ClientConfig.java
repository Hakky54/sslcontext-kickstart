package nl.altindag.ssl.model;

import nl.altindag.ssl.SSLFactory;

import java.net.PasswordAuthentication;
import java.net.Proxy;

public class ClientConfig {

    private final SSLFactory sslFactory;
    private final Proxy proxy;
    private final PasswordAuthentication passwordAuthentication;
    private final Integer timeoutInMilliseconds;

    public ClientConfig(SSLFactory sslFactory, Proxy proxy, PasswordAuthentication passwordAuthentication, Integer timeoutInMilliseconds) {
        this.sslFactory = sslFactory;
        this.proxy = proxy;
        this.passwordAuthentication = passwordAuthentication;
        this.timeoutInMilliseconds = timeoutInMilliseconds;
    }

    public SSLFactory getSslFactory() {
        return sslFactory;
    }

    public Proxy getProxy() {
        return proxy;
    }

    public PasswordAuthentication getPasswordAuthentication() {
        return passwordAuthentication;
    }

    public Integer getTimeoutInMilliseconds() {
        return timeoutInMilliseconds;
    }

}
