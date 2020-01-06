package nl.altindag.sslcontext.trustmanager;

import static java.util.Objects.isNull;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.collect.ImmutableList;

import nl.altindag.sslcontext.util.TrustManagerUtils;

//https://gist.github.com/HughJeffner/6eac419b18c6001aeadb
//https://stackoverflow.com/questions/24555890/using-a-custom-truststore-in-java-as-well-as-the-default-one

public class CompositeX509TrustManager implements X509TrustManager {

    private static final Logger LOGGER = LogManager.getLogger(CompositeX509TrustManager.class);

    private final List<? extends X509TrustManager> trustManagers;
    private X509Certificate[] acceptedIssuers;

    public CompositeX509TrustManager(List<? extends X509TrustManager> trustManagers) {
        this.trustManagers = ImmutableList.copyOf(trustManagers);
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
        if (isNull(acceptedIssuers)) {
            acceptedIssuers = trustManagers.stream()
                                           .map(X509TrustManager::getAcceptedIssuers)
                                           .flatMap(Arrays::stream)
                                           .distinct()
                                           .toArray(X509Certificate[]::new);
        }
        return acceptedIssuers;
    }

    public X509TrustManager[] getTrustManagers() {
        return trustManagers.stream().toArray(X509TrustManager[]::new);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final List<X509TrustManager> trustManagers = new ArrayList<>();

        public <T extends X509TrustManager> Builder withTrustManager(T trustManager) {
            trustManagers.add(trustManager);
            return this;
        }

        public Builder withTrustManagers(List<? extends X509TrustManager> trustManagers) {
            this.trustManagers.addAll(trustManagers);
            return this;
        }

        public <T extends KeyStore> Builder withTrustStore(T... trustStores) {
            for (KeyStore trustStore : trustStores) {
                this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            }
            return this;
        }

        public <T extends KeyStore> Builder withTrustStore(T trustStore, String trustManagerAlgorithm) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore, trustManagerAlgorithm));
            return this;
        }

        public CompositeX509TrustManager build() {
            return new CompositeX509TrustManager(trustManagers);
        }

    }

}
