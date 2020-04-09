package nl.altindag.sslcontext.trustmanager;

import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.util.Objects.isNull;

/**
 * {@link CompositeX509ExtendedTrustManager} is wrapper for a collection of TrustManagers.
 * It has the ability to validate a certificate chain against multiple TrustManagers.
 * If any one of the composed managers trusts a certificate chain, then it is trusted by the composite manager.
 * The TrustManager can be build from one or more of any combination provided within the {@link Builder CompositeX509ExtendedTrustManager.Builder}.
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
public final class CompositeX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(CompositeX509ExtendedTrustManager.class);
    private static final String CERTIFICATE_EXCEPTION_MESSAGE = "None of the TrustManagers trust this certificate chain";
    private static final String NOT_X509_EXTENDED_TRUST_MANAGER_EXCEPTION_MESSAGE =
            "Couldn't validate certificate because TrustManager is not an instance of X509ExtendedTrustManager";
    private static final String CLIENT_CERTIFICATE_LOG_MESSAGE = "Received the following client certificate: [{}]";
    private static final String SERVER_CERTIFICATE_LOG_MESSAGE = "Received the following server certificate: [{}]";

    private final List<? extends X509TrustManager> trustManagers;
    private X509Certificate[] acceptedIssuers;

    public CompositeX509ExtendedTrustManager(List<? extends X509TrustManager> trustManagers) {
        this.trustManagers = Collections.unmodifiableList(trustManagers);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
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

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    ((X509ExtendedTrustManager) trustManager).checkClientTrusted(chain, authType, socket);
                    return;
                } else {
                    certificateExceptions.add(new CertificateException(NOT_X509_EXTENDED_TRUST_MANAGER_EXCEPTION_MESSAGE));
                }
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    ((X509ExtendedTrustManager) trustManager).checkClientTrusted(chain, authType, sslEngine);
                    return;
                } else {
                    certificateExceptions.add(new CertificateException(NOT_X509_EXTENDED_TRUST_MANAGER_EXCEPTION_MESSAGE));
                }
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
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

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    ((X509ExtendedTrustManager) trustManager).checkServerTrusted(chain, authType, socket);
                    return;
                } else {
                    certificateExceptions.add(new CertificateException(NOT_X509_EXTENDED_TRUST_MANAGER_EXCEPTION_MESSAGE));
                }
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509TrustManager trustManager : trustManagers) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    ((X509ExtendedTrustManager) trustManager).checkServerTrusted(chain, authType, sslEngine);
                    return;
                } else {
                    certificateExceptions.add(new CertificateException(NOT_X509_EXTENDED_TRUST_MANAGER_EXCEPTION_MESSAGE));
                }
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
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

    public int size() {
        return trustManagers.size();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

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

        public CompositeX509ExtendedTrustManager build() {
            return new CompositeX509ExtendedTrustManager(trustManagers);
        }

    }

}
