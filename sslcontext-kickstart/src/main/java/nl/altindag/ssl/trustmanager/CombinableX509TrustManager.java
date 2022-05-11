/*
 * Copyright 2019-2022 the original author or authors.
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
package nl.altindag.ssl.trustmanager;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
interface CombinableX509TrustManager extends X509TrustManager {

    String CERTIFICATE_EXCEPTION_MESSAGE = "None of the TrustManagers trust this certificate chain";

    List<X509ExtendedTrustManager> getTrustManagers();

    default void checkTrusted(TrustManagerConsumer callBackConsumer) throws CertificateException {
        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : getTrustManagers()) {
            if (trustManager.getAcceptedIssuers().length > 0) {
                try {
                    callBackConsumer.checkTrusted(trustManager);
                    return;
                } catch (CertificateException e) {
                    certificateExceptions.add(e);
                }
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

}
