/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.keymanager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public class LoggingX509ExtendedKeyManager extends DelegatingX509ExtendedKeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedKeyManager.class);
    private static final String CHOOSE_ALIAS_LOG_MESSAGE_TEMPLATE = "Attempting to find a %s alias for key types %s%s.%s";
    private static final String FOUND_ALIAS_LOG_MESSAGE_TEMPLATE = "Found the following %s alias: %s";

    public LoggingX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
        super(keyManager);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        logChooseAlias(ServerOrClient.CLIENT, keyType, issuers, socket, null);

        String alias = super.chooseClientAlias(keyType, issuers, socket);
        logFoundAlias(ServerOrClient.CLIENT, alias);

        return alias;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        logChooseAlias(ServerOrClient.CLIENT, keyTypes, issuers, null, sslEngine);

        String alias = super.chooseEngineClientAlias(keyTypes, issuers, sslEngine);
        logFoundAlias(ServerOrClient.CLIENT, alias);

        return alias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        logChooseAlias(ServerOrClient.SERVER, keyType, issuers, socket, null);

        String alias = super.chooseServerAlias(keyType, issuers, socket);
        logFoundAlias(ServerOrClient.SERVER, alias);

        return alias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        logChooseAlias(ServerOrClient.SERVER, keyType, issuers, null, sslEngine);

        String alias = super.chooseEngineServerAlias(keyType, issuers, sslEngine);
        logFoundAlias(ServerOrClient.SERVER, alias);

        return alias;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        LOGGER.info("Attempting to get the private key for the alias: " + alias);

        PrivateKey privateKey = super.getPrivateKey(alias);
        if (privateKey != null) {
            String logMessage = String.format("Found a private key for the alias: %s", alias);
            LOGGER.info(logMessage);
        }
        return privateKey;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        LOGGER.info("Attempting to get the certificate chain for the alias: " + alias);

        X509Certificate[] certificateChain = super.getCertificateChain(alias);
        if (certificateChain != null && certificateChain.length > 0) {
            String combinedCertificateChain = Arrays.toString(certificateChain);
            String logMessage = String.format("Found the certificate chain with a size of %d for the alias: %s. See below for the full chain:\n%s",
                    certificateChain.length, alias, combinedCertificateChain);
            LOGGER.info(logMessage);
        }

        return certificateChain;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        String[] clientAliases = super.getClientAliases(keyType, issuers);
        return clientAliases;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        String[] serverAliases = super.getServerAliases(keyType, issuers);
        return serverAliases;
    }

    private void logChooseAlias(ServerOrClient serverOrClient, String keyType, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        logChooseAlias(serverOrClient, new String[]{keyType}, issuers, socket, sslEngine);
    }

    private void logChooseAlias(ServerOrClient serverOrClient, String[] keyTypes, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        String combinedKeyTypes = Arrays.toString(keyTypes);

        String issuersLogMessage = Optional.ofNullable(issuers)
                .filter(principals -> principals.length > 0)
                .map(Arrays::toString)
                .map(combinedIssuers -> String.format(" See below for list of the issuers:\n%s", combinedIssuers))
                .orElse("");

        Optional<String> classNameLogMessage = getClassnameOfEitherOrOther(socket, sslEngine)
                .map(className -> ", while also using the " + className + "");

        String logMessage = String.format(CHOOSE_ALIAS_LOG_MESSAGE_TEMPLATE, serverOrClient, combinedKeyTypes, classNameLogMessage.orElse(""), issuersLogMessage);
        LOGGER.info(logMessage);
    }

    static Optional<String> getClassnameOfEitherOrOther(Socket socket, SSLEngine sslEngine) {
        if (socket != null) {
            return Optional.of(Socket.class.getSimpleName());
        }

        if (sslEngine != null) {
            return Optional.of(SSLEngine.class.getSimpleName());
        }

        return Optional.empty();
    }

    private void logFoundAlias(ServerOrClient serverOrClient, String alias) {
        if (alias != null) {
            String logMessage = String.format(FOUND_ALIAS_LOG_MESSAGE_TEMPLATE, serverOrClient, alias);
            LOGGER.info(logMessage);
        }
    }

    private enum ServerOrClient {
        SERVER, CLIENT;

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }

}
