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
package nl.altindag.ssl.pem;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.ServerUtils.Server;
import nl.altindag.ssl.pem.util.PemUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    private static Server server;

    @BeforeAll
    static void startServer() {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        server = ServerUtils.createServer(sslFactoryForServer);
    }

    @AfterAll
    static void stopServer() {
        server.stop();
    }

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("pem/client-one/identity.pem", "secret".toCharArray());
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("pem/client-one/trust.pem");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(trustManager)
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:8443/api/hello").openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        assertThat(connection.getResponseCode()).isEqualTo(200);
    }

    @Test
    void executeHttpsRequestWithMutualAuthenticationFromRawSslMaterial() throws IOException {
        String identityMaterial =
                "Bag Attributes\n" +
                        "    friendlyName: client-one\n" +
                        "    localKeyID: 54 69 6D 65 20 31 36 31 32 39 30 39 36 39 33 35 34 30 \n" +
                        "Key Attributes: <No Attributes>\n" +
                        "-----BEGIN PRIVATE KEY-----\n" +
                        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA9JRTOTpYphfE\n" +
                        "5U51j6U7Mk/LwZVVjunBqZGJWXMY0S8bTdADmWH9TxZcsoZb3XC4ZquF+C+XJ+jL\n" +
                        "H5/RzUc3EbwOkIPOn9eK5CENLMdpQT0fJPDI2AAiw38EFc9PC0ULxdcc1gxsu5cB\n" +
                        "vDsz4H14aTF/LoAwRdQjNed+aq3wklXIpK9gFsOmYyhoD0aaLO3ZhQokOPd6NHCe\n" +
                        "f5djhhCCf8CFXXUloKq0GKVQsa38nUcdFTftmKj9rnXEDbrgipDoTeQTSXwJCPRR\n" +
                        "ZTiQkaVsSX2fZ8O9GbDh9IshioOpt0TV3/r8emqXBCmHrBWZg9xXxm22kFuZx1Pz\n" +
                        "VfTod0u9AgMBAAECggEARinpsaWSsN+crw1PDXKxe6gc2hPHkLgKClD1ygML1k9i\n" +
                        "mMQfyt9AgZL7p7OHJeqM7ZDv+CQ6cfWiMhKK1AiYR88cGhO0yjLXdvrjhd3tmTmO\n" +
                        "1z9gizf4PKvoCP1BSBXqApDrWuH+3J8OFyRyRrfwCBQAWqX3GRabQD5+sjpqi5qY\n" +
                        "CaINOTTqV2Im1TU0iAJ9DkP6NbizxUcNv840/QBnL0JBtfcQXYcuoMczM9MYpdAX\n" +
                        "Bnqv5QDx9E7L5PEZD1f5bfko30PAodPdnoTncJZn4w4rX16yVgrraYnU8I4Wpw41\n" +
                        "769QSAr3h6nyoBlHAVaoNcHajECd/u+PkHOR5/teYQKBgQD41Up03hUrjiwkKN9D\n" +
                        "r4KdhmnDnereDDMo/uzvVM5S7NEyzm+BEsMlZKLzV+wsZnNOtjj7MAbwZVmYlM9K\n" +
                        "5ijubvWwjNm21tjwxi/u+1kMbihEn/Bc/IdhIp7fQCwtMA3dHqKgEiIk5oJwjJqu\n" +
                        "BSBveUWGSm5j8+6h9ldrgOWxFQKBgQDGg0mnmp2Iy1kvgJNZLNO0BBMz8ZQnyBpG\n" +
                        "33U2yc/2ZMcyXs1QkcIjDQf5NCmb1L2gB4k/uC2latRqgKCygtywtUfBpu+l2sAj\n" +
                        "fL5OWOIYbzwmJm2TSCtBcciF5vGG1ehNLDMCulsy33eL587dmUpeSZJK4mHcJv7K\n" +
                        "+YioU2RKCQKBgCN8N0wHR7mYYs8dTQmYA+Z2/qo44P+decZE5IEU9P96ajL2oYwk\n" +
                        "otO4UEynozSJv7Pf5Kxdov+xVF+gCRfDTt8Bz+PHklyysulTOg64pXBSXUe8D0kT\n" +
                        "cjL1/vYTbrla+v8nmUV+kIP2o29tfbmHXaLIBpQqFSgH52YNfVYFYbwpAoGAHI+F\n" +
                        "CFUpdyXylfAEwx688rhnXuDR9QtIJIw/2/sbLZMASdHz7jSaXtqgHA2SMvZfted/\n" +
                        "qqhAAP2mxA/vjt9fCxl50nXHIvCfFjv7UWBeXy+Z0s9Sko8ekhLhy8oXU9Pw0TGb\n" +
                        "wTe4qVAXbgyS6bUFSx2Aq794XulJXUCblcQxuKkCgYAC3AVvT5idTURwRMz3rP9X\n" +
                        "R7nUSrSS+rjIqivOyxzYsnOx/1bw8ze9fR5MdptgHdj4Nx7dzt9DOsy1n4ohOS/Z\n" +
                        "8dmrc4LUan4uc1KtqHEVBGLJeX1/raNA4H4g+lE5/nYnKZAQExUjZ7tjxyH4Gb9I\n" +
                        "7WGhLyfp+B/7lbcWNSAfhA==\n" +
                        "-----END PRIVATE KEY-----\n" +
                        "Bag Attributes\n" +
                        "    friendlyName: client-one\n" +
                        "    localKeyID: 54 69 6D 65 20 31 36 31 32 39 30 39 36 39 33 35 34 30 \n" +
                        "subject=/C=NL/O=Altindag/OU=Altindag/CN=ClientOne\n" +
                        "issuer=/C=NL/O=Altindag/OU=Altindag/CN=ClientOne\n" +
                        "-----BEGIN CERTIFICATE-----\n" +
                        "MIIDWTCCAkGgAwIBAgIEOgPHGTANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJO\n" +
                        "TDERMA8GA1UEChMIQWx0aW5kYWcxETAPBgNVBAsTCEFsdGluZGFnMRIwEAYDVQQD\n" +
                        "EwlDbGllbnRPbmUwHhcNMjEwMjA4MTcxNDE2WhcNMzEwMjA2MTcxNDE2WjBHMQsw\n" +
                        "CQYDVQQGEwJOTDERMA8GA1UEChMIQWx0aW5kYWcxETAPBgNVBAsTCEFsdGluZGFn\n" +
                        "MRIwEAYDVQQDEwlDbGllbnRPbmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                        "AoIBAQDA9JRTOTpYphfE5U51j6U7Mk/LwZVVjunBqZGJWXMY0S8bTdADmWH9TxZc\n" +
                        "soZb3XC4ZquF+C+XJ+jLH5/RzUc3EbwOkIPOn9eK5CENLMdpQT0fJPDI2AAiw38E\n" +
                        "Fc9PC0ULxdcc1gxsu5cBvDsz4H14aTF/LoAwRdQjNed+aq3wklXIpK9gFsOmYyho\n" +
                        "D0aaLO3ZhQokOPd6NHCef5djhhCCf8CFXXUloKq0GKVQsa38nUcdFTftmKj9rnXE\n" +
                        "DbrgipDoTeQTSXwJCPRRZTiQkaVsSX2fZ8O9GbDh9IshioOpt0TV3/r8emqXBCmH\n" +
                        "rBWZg9xXxm22kFuZx1PzVfTod0u9AgMBAAGjTTBLMB0GA1UdDgQWBBRs0sY9kJQf\n" +
                        "yUOaqKNBPryT/+kAnjALBgNVHQ8EBAMCA7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n" +
                        "CCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBfzbgNJyNGgYCWoONNeYLzrOT8\n" +
                        "U7aLF/2I5wPftabceHXXV74UxhJEoyXimyvh8fpoGRnzG+dnF48S9seCyrfi+WZE\n" +
                        "CTzXD+EL+89LWDd5Mtzh4c2Xm5nIldrzDnQNNn6k4Nq8ZqDNrQy+bcUSfvJurIkA\n" +
                        "VRsaI8omDbO45VKM9iDT7aPXzVUvLesHEh5wxg4fPKuMIy8VGaT2TrAO9SrZ4fJQ\n" +
                        "qbxteiTKygdpYQ5VxcM2ci24SpMuGUX5ScHIFBWZxwaNKpMIhwuJvj1yAaXnlyqz\n" +
                        "6mOSRTLTWFW+u2m4IVqY0n0Ljb0jojvDU5RaVLry/UitWfbhy4a/7xIOvWke\n" +
                        "-----END CERTIFICATE-----\n";

        String trustMaterial =
                "Bag Attributes\n" +
                        "    friendlyName: server\n" +
                        "    2.16.840.1.113894.746875.1.1: <Unsupported tag 6>\n" +
                        "subject=/C=NL/O=Thunderberry/OU=Amsterdam/CN=ServerOne\n" +
                        "issuer=/C=NL/O=Thunderberry/OU=Amsterdam/CN=ServerOne\n" +
                        "-----BEGIN CERTIFICATE-----\n" +
                        "MIIDlTCCAn2gAwIBAgIER6eBrzANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJO\n" +
                        "TDEVMBMGA1UEChMMVGh1bmRlcmJlcnJ5MRIwEAYDVQQLEwlBbXN0ZXJkYW0xEjAQ\n" +
                        "BgNVBAMTCVNlcnZlck9uZTAeFw0yMTAyMDgxNzE0MTVaFw0zMTAyMDYxNzE0MTVa\n" +
                        "MEwxCzAJBgNVBAYTAk5MMRUwEwYDVQQKEwxUaHVuZGVyYmVycnkxEjAQBgNVBAsT\n" +
                        "CUFtc3RlcmRhbTESMBAGA1UEAxMJU2VydmVyT25lMIIBIjANBgkqhkiG9w0BAQEF\n" +
                        "AAOCAQ8AMIIBCgKCAQEAgEn0tb81HuFyuI/RF+UygYt3cO5eY/wQGwO+v/k56e4a\n" +
                        "lmVj8fkHEJS7Y82/GP5TYw5NpikwcAmvWkJoM9d9GBKh4gMEpe2TzltHpmgUJUgR\n" +
                        "GaZWkuy8dh7xIPe0bToY85y8/NsDGyDIfeW3Tdb5ML00+nZpwWPoe1YVtcmtx4mU\n" +
                        "9at1R1tdZkqNqVZ97jZqqcSSsG96PP1HgdbtihiQNOd02Xef2t6cRaaOAk4BYByn\n" +
                        "L6UVTRhyttuKd89/Zf7efEd1dRvzxFbVt15Ly/8J6wnXo1WwE8y6SiLF9wKV8fUo\n" +
                        "9GGLB+DmKz2Ecl3kYdXXumGA4MbzumNyx9IwvJGLtQIDAQABo38wfTAdBgNVHQ4E\n" +
                        "FgQU3kFZnLymDVjQtTsIdCXKhuX7yjcwCwYDVR0PBAQDAgO4MDAGA1UdEQEB/wQm\n" +
                        "MCSCCWxvY2FsaG9zdIIRcmFzcGJlcnJ5cGkubG9jYWyHBH8AAAEwHQYDVR0lBBYw\n" +
                        "FAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAr+9+URNsm\n" +
                        "44k09K1oKIRI5CSJD0bBUTZPU5+tdP7xYy+HF7sfNOw8RSIUiF7w1fwR1rIeNRox\n" +
                        "+BUcpKjePJBuCAKwfdXd6AT0KNayKudW1YBkUKxhDmpVSqP/AOcXBVrsoHHAVQmI\n" +
                        "7EmP89lcOLH/4IVbowqP6u9xDj1YxmLwCtykQiIUkKJ1+R8KO+e9vctB0KpQmeyv\n" +
                        "Kp+0AC0YjKsgPt4s64t91SzFQv4muowxssIGNDk7sldXLZGwRKo1Uth2YjX6Mz7b\n" +
                        "xsCHrVeZYB1Ka6fm+DKCzPtofhsLhpgFPSi898hu7zF+k/ibYshBrcrXAURmMB4J\n" +
                        "ZbfxqrUzcq7W\n" +
                        "-----END CERTIFICATE-----\n";

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityMaterial);
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(trustMaterial);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(trustManager)
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:8443/api/hello").openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        assertThat(connection.getResponseCode()).isEqualTo(200);
    }
}
