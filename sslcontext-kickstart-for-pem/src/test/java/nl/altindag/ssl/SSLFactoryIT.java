/*
 * Copyright 2019-2021 the original author or authors.
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
package nl.altindag.ssl;

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.PemUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    private static final String BADSSL_URL = "https://client.badssl.com/";
    private static final char[] IDENTITY_PASSWORD = "badssl.com".toCharArray();

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("pem/badssl-identity.pem", IDENTITY_PASSWORD);
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("pem/badssl-certificate.pem");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(trustManager)
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(BADSSL_URL).openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        logCaptor.close();

        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(connection.getResponseCode()).isEqualTo(200);
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthenticationWithUnencryptedPrivateKey() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("pem/unencrypted-badssl-identity.pem", IDENTITY_PASSWORD);
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("pem/badssl-certificate.pem");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(trustManager)
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(BADSSL_URL).openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        logCaptor.close();

        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(connection.getResponseCode()).isEqualTo(200);
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthenticationFromRawSslMaterial() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        String identityMaterial =
                "Bag Attributes\n" +
                "    localKeyID: 41 C3 6C 33 C7 E3 36 DD EA 4A 1F C0 B7 23 B8 E6 9C DC D8 0F\n" +
                "subject=C = US, ST = California, L = San Francisco, O = BadSSL, CN = BadSSL Client Certificate\n" +
                "\n" +
                "issuer=C = US, ST = California, L = San Francisco, O = BadSSL, CN = BadSSL Client Root Certificate Authority\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIEqDCCApCgAwIBAgIUK5Ns4y2CzosB/ZoFlaxjZqoBTIIwDQYJKoZIhvcNAQEL\n" +
                "BQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n" +
                "DVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDExMC8GA1UEAwwoQmFkU1NM\n" +
                "IENsaWVudCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTExMjcwMDE5\n" +
                "NTdaFw0yMTExMjYwMDE5NTdaMG8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp\n" +
                "Zm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wx\n" +
                "IjAgBgNVBAMMGUJhZFNTTCBDbGllbnQgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDHN18R6x5Oz+u6SOXLoxIscz5GHR6cDcCLgyPa\n" +
                "x2XfXHdJs+h6fTy61WGM+aXEhR2SIwbj5997s34m0MsbvkJrFmn0LHK1fuTLCihE\n" +
                "EmxGdCGZA9xrwxFYAkEjP7D8v7cAWRMipYF/JP7VU7xNUo+QSkZ0sOi9k6bNkABK\n" +
                "L3+yP6PqAzsBoKIN5lN/YRLrppsDmk6nrRDo4R3CD+8JQl9quEoOmL22Pc/qpOjL\n" +
                "1jgOIFSE5y3gwbzDlfCYoAL5V+by1vu0yJShTTK8oo5wvphcFfEHaQ9w5jFg2htd\n" +
                "q99UER3BKuNDuL+zejqGQZCWb0Xsk8S5WBuX8l3Brrg5giqNAgMBAAGjLTArMAkG\n" +
                "A1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgeAMAsGA1UdDwQEAwIF4DANBgkqhkiG\n" +
                "9w0BAQsFAAOCAgEAZBauLzFSOijkDadcippr9C6laHebb0oRS54xAV70E9k5GxfR\n" +
                "/E2EMuQ8X+miRUMXxKquffcDsSxzo2ac0flw94hDx3B6vJIYvsQx9Lzo95Im0DdT\n" +
                "DkHFXhTlv2kjQwFVnEsWYwyGpHMTjanvNkO7sBP9p1bN1qTE3QAeyMZNKWJk5xPl\n" +
                "U298ERar6tl3Z2Cl8mO6yLhrq4ba6iPGw08SENxzuAJW+n8r0rq7EU+bMg5spgT1\n" +
                "CxExzG8Bb0f98ZXMklpYFogkcuH4OUOFyRodotrotm3iRbuvZNk0Zz7N5n1oLTPl\n" +
                "bGPMwBcqaGXvK62NlaRkwjnbkPM4MYvREM0bbAgZD2GHyANBTso8bdWvhLvmoSjs\n" +
                "FSqJUJp17AZ0x/ELWZd69v2zKW9UdPmw0evyVR19elh/7dmtF6wbewc4N4jxQnTq\n" +
                "IItuhIWKWB9edgJz65uZ9ubQWjXoa+9CuWcV/1KxuKCbLHdZXiboLrKm4S1WmMYW\n" +
                "d0sJm95H9mJzcLyhLF7iX2kK6K9ug1y02YCVXBC9WGZc2x6GMS7lDkXSkJFy3EWh\n" +
                "CmfxkmFGwOgwKt3Jd1pF9ftcSEMhu4WcMgxi9vZr9OdkJLxmk033sVKI/hnkPaHw\n" +
                "g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=\n" +
                "-----END CERTIFICATE-----\n" +
                "Bag Attributes\n" +
                "    localKeyID: 41 C3 6C 33 C7 E3 36 DD EA 4A 1F C0 B7 23 B8 E6 9C DC D8 0F\n" +
                "Key Attributes: <No Attributes>\n" +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
                "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECFOXAIo35o51BIIEyLsnLgbzRpsI\n" +
                "qsephRcXVWt4lXgWF1uHD+mFL9JMqC8K1ESV/SUbIAaINziWlyBjkkCduPMOHbER\n" +
                "6zUP60ixisPi8jkihkV1bvJvWeHXsQjjTAYXtwVX2s9T5D+IYK4CF8lOe5eiG1Pb\n" +
                "UV3oD78zcOeM+aGRjSDKneSx4bUFiv33bziBDAtnk6Ts5lg6x5HtM0YQBCycqpMH\n" +
                "I7jpafH+TZSVqdyAdL8Jc5bByAQk8SWvEFXxPP5RS9YfeOd3WDvzJQaHSw8otf6h\n" +
                "lpimxbXhOrI84r1YZwDy/3QaYdnKUPBYSZniBje2G/g0Su5ZanCvvhhhhQlN18QO\n" +
                "AjQGEZKlfuxi8cq/EZWqFrnui6KSiutCmcnMyJ8mcS2dDGVsr3GVPpnyzpokSTY1\n" +
                "q2o/b9hqV/9ETzVYeNyO4L5MVIuxTxM8hNj4gkmFMkv8diDS6TmKO2kOasZAuUYO\n" +
                "Eq+diZKj1CZg+qejf3u+93fycyk9b1rrsL6iG24QMdHgTsn/ZyX85ZUHFXba+qWn\n" +
                "G2rZsseBR4UcKxjUWO7ElH6oD8WUP/St7/88q5XFV1AuC0CGc6L+a4je3EbKjhK8\n" +
                "9fFXgSXbYMPIOQ1y0ShHt3YNpRKOCoV2mwZE1FtVIGGlUlu30kY/Ov93sXGYUvtm\n" +
                "/b+GMQrc7tZq7l5qNoI253zfhgX2gWOmU092JAPoDvzDz0QP2vVjB4BqlNJKuOBP\n" +
                "IKBckCQbj4mKWy27LVCMZfylU08k5KfUyvEHxwmD5aj+LClZzGS1GkeQcG80RYrl\n" +
                "DGeLkQXC+li/cSxmKhQ2RPfZ4xR1ImzQdFQJsm9dcHq5arwU5W/N2t3c/0mORKIp\n" +
                "j5mJCm8IVlVP05Rnxmz2wtL+VnUt7M9BQjeUDs155X4Rqp8j24bCtonp8fCnejjw\n" +
                "fBu83zTjo+a8eHTWsyjfJyDnTSNq1HgyWDGhkTSWLW7+UVrG8bUuuGI+C0HtRuPp\n" +
                "49XHrcHXBSufM+t8YHf+DebZ/7dJNnL1DqVOGaFh5fyYJNtMAd1IyT9NkCOq6d22\n" +
                "p1bXFQF5IWrrNJ1FMRT6GzkAUYHd86jGJUuNm1vPqAAF/8eoow2PK75Qu8G+hIjY\n" +
                "k03mUAZzQn12tHidMAVS08frmYBMwmIEwWK+AlOGA8jJoyfJ06dRDN8qcIQ3RQSP\n" +
                "uH/chBsmO/0HPKQYE19fAqqxLQqzaU1yqq6UStTyDCvsuZdJnAwQEi43Wzt3EkNk\n" +
                "50i5fZp6me1x80LARRZFDv5YjEb+hbK4BjKPAoRHL1BbYM5uhGV2F08Y6qqVBhK0\n" +
                "uG1ykwxhnNkS49/7dVwoayBKHHvCbeoOw+E3qmvKfc3jpI93osYGCzFPP0+dKpZN\n" +
                "szfrkI35gVnPSdh0SCSBMLcqkeFMyAeKH4fL13KckU0swe2WSYk/JZlay5Ba+HRM\n" +
                "5zd/j0SAGYYOjvBMrhbLU5g9q2llanv7i8zEHKcb3LzeEaD7XoK5OEHnth9c5Lyx\n" +
                "HD2IxzftLN5J1pXHvioi+KTNJNS4z2k35AQCyNez+g8gFmuhsssYD9dUjEjhbNra\n" +
                "C+D/XlHAZDESksribfm4nTuOOQiyVzdKJ8Xmxsy9Ckjcq5gn5jNvsv96eP2QC5ok\n" +
                "FHeRMpMdlCLXw78iQ6HjJw==\n" +
                "-----END ENCRYPTED PRIVATE KEY-----\n";

        String trustMaterial =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIGqDCCBZCgAwIBAgIQCvBs2jemC2QTQvCh6x1Z/TANBgkqhkiG9w0BAQsFADBN\n" +
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\n" +
                "aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMjAwMzIzMDAwMDAwWhcN\n" +
                "MjIwNTE3MTIwMDAwWjBuMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p\n" +
                "YTEVMBMGA1UEBxMMV2FsbnV0IENyZWVrMRwwGgYDVQQKExNMdWNhcyBHYXJyb24g\n" +
                "VG9ycmVzMRUwEwYDVQQDDAwqLmJhZHNzbC5jb20wggEiMA0GCSqGSIb3DQEBAQUA\n" +
                "A4IBDwAwggEKAoIBAQDCBOz4jO4EwrPYUNVwWMyTGOtcqGhJsCK1+ZWesSssdj5s\n" +
                "wEtgTEzqsrTAD4C2sPlyyYYC+VxBXRMrf3HES7zplC5QN6ZnHGGM9kFCxUbTFocn\n" +
                "n3TrCp0RUiYhc2yETHlV5NFr6AY9SBVSrbMo26r/bv9glUp3aznxJNExtt1NwMT8\n" +
                "U7ltQq21fP6u9RXSM0jnInHHwhR6bCjqN0rf6my1crR+WqIW3GmxV0TbChKr3sMP\n" +
                "R3RcQSLhmvkbk+atIgYpLrG6SRwMJ56j+4v3QHIArJII2YxXhFOBBcvm/mtUmEAn\n" +
                "hccQu3Nw72kYQQdFVXz5ZD89LMOpfOuTGkyG0cqFAgMBAAGjggNhMIIDXTAfBgNV\n" +
                "HSMEGDAWgBQPgGEcgjFh1S8o541GOLQs4cbZ4jAdBgNVHQ4EFgQUne7Be4ELOkdp\n" +
                "cRh9ETeTvKUbP/swIwYDVR0RBBwwGoIMKi5iYWRzc2wuY29tggpiYWRzc2wuY29t\n" +
                "MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n" +
                "awYDVR0fBGQwYjAvoC2gK4YpaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NzY2Et\n" +
                "c2hhMi1nNi5jcmwwL6AtoCuGKWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zc2Nh\n" +
                "LXNoYTItZzYuY3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAEBMCowKAYIKwYBBQUH\n" +
                "AgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQIDMHwGCCsG\n" +
                "AQUFBwEBBHAwbjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t\n" +
                "MEYGCCsGAQUFBzAChjpodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl\n" +
                "cnRTSEEyU2VjdXJlU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQCMAAwggF+BgorBgEE\n" +
                "AdZ5AgQCBIIBbgSCAWoBaAB2ALvZ37wfinG1k5Qjl6qSe0c4V5UKq1LoGpCWZDaO\n" +
                "HtGFAAABcQhGXioAAAQDAEcwRQIgDfWVBXEuUZC2YP4Si3AQDidHC4U9e5XTGyG7\n" +
                "SFNDlRkCIQCzikrA1nf7boAdhvaGu2Vkct3VaI+0y8p3gmonU5d9DwB2ACJFRQdZ\n" +
                "VSRWlj+hL/H3bYbgIyZjrcBLf13Gg1xu4g8CAAABcQhGXlsAAAQDAEcwRQIhAMWi\n" +
                "Vsi2vYdxRCRsu/DMmCyhY0iJPKHE2c6ejPycIbgqAiAs3kSSS0NiUFiHBw7QaQ/s\n" +
                "GO+/lNYvjExlzVUWJbgNLwB2AFGjsPX9AXmcVm24N3iPDKR6zBsny/eeiEKaDf7U\n" +
                "iwXlAAABcQhGXnoAAAQDAEcwRQIgKsntiBqt8Au8DAABFkxISELhP3U/wb5lb76p\n" +
                "vfenWL0CIQDr2kLhCWP/QUNxXqGmvr1GaG9EuokTOLEnGPhGv1cMkDANBgkqhkiG\n" +
                "9w0BAQsFAAOCAQEA0RGxlwy3Tl0lhrUAn2mIi8LcZ9nBUyfAcCXCtYyCdEbjIP64\n" +
                "xgX6pzTt0WJoxzlT+MiK6fc0hECZXqpkTNVTARYtGkJoljlTK2vAdHZ0SOpm9OT4\n" +
                "RLfjGnImY0hiFbZ/LtsvS2Zg7cVJecqnrZe/za/nbDdljnnrll7C8O5naQuKr4te\n" +
                "uice3e8a4TtviFwS/wdDnJ3RrE83b1IljILbU5SV0X1NajyYkUWS7AnOmrFUUByz\n" +
                "MwdGrM6kt0lfJy/gvGVsgIKZocHdedPeECqAtq7FAJYanOsjNN9RbBOGhbwq0/FP\n" +
                "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
                "-----END CERTIFICATE-----\n";

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityMaterial, IDENTITY_PASSWORD);
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(trustMaterial);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(trustManager)
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(BADSSL_URL).openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        logCaptor.close();

        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(connection.getResponseCode()).isEqualTo(200);
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }
}
