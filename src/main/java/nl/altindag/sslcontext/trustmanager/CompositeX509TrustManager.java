package nl.altindag.sslcontext.trustmanager;

import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.util.Objects.isNull;

/**
 * {@link CompositeX509TrustManager} is wrapper for a collection of TrustManagers.
 * It has the ability to validate a certificate chain against multiple TrustManagers.
 * If any one of the composed managers trusts a certificate chain, then it is trusted by the composite manager.
 * The TrustManager can be build from one or more of any combination provided within the {@link Builder CompositeX509TrustManager.Builder}.
 * <br><br>
 * This includes:
 * <pre>
 *     - Any amount of custom TrustManagers
 *     - Any amount of custom TrustStores
 * </pre>
 *
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 * @see <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">
 *     http://codyaray.com/2013/04/java-ssl-with-multiple-keystores
 *     </a>
 */
public class CompositeX509TrustManager implements X509TrustManager {

    private static final Logger LOGGER = LogManager.getLogger(CompositeX509TrustManager.class);

    private final List<? extends X509TrustManager> trustManagers;
    private X509Certificate[] acceptedIssuers;

    public CompositeX509TrustManager(List<? extends X509TrustManager> trustManagers) {
        this.trustManagers = Collections.unmodifiableList(trustManagers);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Received the following client certificate: [{}]", chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException("None of the TrustManagers trust this certificate chain");
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Received the following server certificate: [{}]", chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException("None of the TrustManagers trust this certificate chain");
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
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

        public <T extends X509TrustManager> Builder withTrustManagers(T... trustManagers) {
            return withTrustManagers(Arrays.asList(trustManagers));
        }

        public Builder withTrustManagers(List<? extends X509TrustManager> trustManagers) {
            this.trustManagers.addAll(trustManagers);
            return this;
        }

        public <T extends KeyStore> Builder withTrustStores(T... trustStores) {
            return withTrustStores(Arrays.asList(trustStores));
        }

        public Builder withTrustStores(List<? extends KeyStore> trustStores) {
            for (KeyStore trustStore : trustStores) {
                this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            }
            return this;
        }

        public <T extends KeyStore> Builder withTrustStore(T trustStore) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
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
