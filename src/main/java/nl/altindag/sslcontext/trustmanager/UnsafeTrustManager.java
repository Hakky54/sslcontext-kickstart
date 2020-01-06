package nl.altindag.sslcontext.trustmanager;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

public final class UnsafeTrustManager implements X509TrustManager {

    public static final UnsafeTrustManager INSTANCE = new UnsafeTrustManager();

    private UnsafeTrustManager() {}

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {}

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

}
