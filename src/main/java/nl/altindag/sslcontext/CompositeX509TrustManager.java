package nl.altindag.sslcontext;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import nl.altindag.sslcontext.util.TrustManagerUtils;

//https://gist.github.com/HughJeffner/6eac419b18c6001aeadb
//https://stackoverflow.com/questions/24555890/using-a-custom-truststore-in-java-as-well-as-the-default-one

public class CompositeX509TrustManager implements X509TrustManager {

    private static final Logger LOGGER = LogManager.getLogger(CompositeX509TrustManager.class);

    private final List<X509TrustManager> trustManagers = new ArrayList<>();

    public CompositeX509TrustManager(List<X509TrustManager> trustManagers) {
        this.trustManagers.addAll(trustManagers);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        for (CertificateException certificateException : certificateExceptions) {
            LOGGER.error(certificateException.getMessage(), certificateException);
        }

        throw new CertificateException("None of the TrustManagers trust this client certificate chain");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        for (CertificateException certificateException : certificateExceptions) {
            LOGGER.error(certificateException.getMessage(), certificateException);
        }

        throw new CertificateException("None of the TrustManagers trust this server certificate chain");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManagers.stream()
                            .map(X509TrustManager::getAcceptedIssuers)
                            .flatMap(Arrays::stream)
                            .distinct()
                            .toArray(X509Certificate[]::new);
    }

    public X509TrustManager[] getTrustManagers() {
        return trustManagers.stream().toArray(X509TrustManager[]::new);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final List<X509TrustManager> trustManagers = new ArrayList<>();
        private boolean includeDefaultJdkTrustStore = false;

        public Builder withX509TrustManager(X509TrustManager trustManager) {
            trustManagers.add(trustManager);
            return this;
        }

        public Builder withX509TrustManagers(List<X509TrustManager> trustManagers) {
            this.trustManagers.addAll(trustManagers);
            return this;
        }

        public Builder withTrustStore(KeyStore... trustStores) {
            for (KeyStore trustStore : trustStores) {
                this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            }
            return this;
        }

        public Builder withTrustStore(KeyStore keystore, String trustManagerAlgorithm) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(keystore, trustManagerAlgorithm));
            return this;
        }

        public Builder withDefaultJdkTrustStore(boolean includeDefaultJdkTrustStore) {
            this.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;
            return this;
        }

        public CompositeX509TrustManager build() {
            if (includeDefaultJdkTrustStore) {
                this.trustManagers.add(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
            }
            return new CompositeX509TrustManager(trustManagers);
        }

    }

}
