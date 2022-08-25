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
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com]");
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
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com]");
        }
    }

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthenticationFromRawSslMaterial() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        String identityMaterial =
                "Bag Attributes\n" +
                "    friendlyName: 1\n" +
                "    localKeyID: 54 69 6D 65 20 31 36 35 34 32 37 38 30 37 32 35 36 35\n" +
                "Key Attributes: <No Attributes>\n" +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIrMy2KS07LgsCAggA\n" +
                "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECBx8rSKjLpExBIIEyJTGV9ly5pw1\n" +
                "nJdAbOEio8MGklDHnW9oxixH2CfF8fyQC85tI+XJ49KavpY58w+BvtRB8TCb1MoE\n" +
                "odX2cFBwe5JELxbAKuuYqy+Rvre+ggmabMXCHjg8kkNxwxgEUViS6c9mpUsR9+l5\n" +
                "YPp25ljVkBg0ojPByCz/bHk9HcJesHiU0FmfR0qW8QJEI5ySNG9pTzo6JCmLMc0C\n" +
                "rsFH/VfU5kR7R4xrgej1UUcF9p2XL50gvJuhn80fjNMpqBlb7hWgCIcECKw8uhP4\n" +
                "nWRelSDUecLZpqR33rHLVJXGp+1R22Mtkf4zw3pIeorlSCs4jnDnvkXPSzZQ+v8L\n" +
                "LmoG9zVUirjV8lz+buvPBo/12v3WqZSOac5u5Ki/dHplFz3Dm3XsnD7gsCuHPvm8\n" +
                "3FmesgbdNuu/jaxG8rpH0U4MvtvFMfjkmyG8YD5DHIb7fROTMGeOhp0DvsilT2G3\n" +
                "iQrskOQwg1VuOpvT7dR9RFBB5dxD8C1d6YLgLiN33dPHqVuapNWT5d9yESSnV2gs\n" +
                "4+WHASxZFquHLGWHlryXrJwGSq1bXwafDt8Hdyx8To2HRMaslt5yKwvBPXHVdNwd\n" +
                "3hhikQjodLGZhF8Hp3q6npc5HvbOGRqzCfx/xfr3T1x798BCNjy5MkXOXp8A3Ic1\n" +
                "OEAOabuoLKi+/tvr0eVnKQiJM3gfGpR+La609Vey7uwgi/r2ZfeOdMymWjh3iPFt\n" +
                "Yh9Uso7CtpaGB+FLki6LkIcr9J9YndA1oFS9Y+U+2QqJt5l7Tb4JV1vra8QL/JRa\n" +
                "0+wWzCXR/htCWXbxSo/coPpnESAY2zmbDSDv8SD1GEwU/hd+Guq9UALnlOpCtQD8\n" +
                "sKaFv2lxR8/rHoFZRA8Cvunj6AgZYXWHONhbtSg1uA+5D8098ydLLnPie6X5wDUQ\n" +
                "0JH+0HDi8NcNqtm9kZzrO338H2ZJyGHdG6KLQ/fV1SrI9XQEdP8FNZPZGjdJrOLb\n" +
                "t5zhXqYQajfHWRzumQ3GGUIGDfP7+lNImrGPwVY9n/d9Ok9SdJ7vq+pTqsU56dbe\n" +
                "yTTHGfE2TZ5U/sn5a8ypRfC5gUoXSieVklNWlKRi3/qjt6HaPMGoFmsaBCbX3+6Y\n" +
                "WTKEKbO3JA5GlFIU6SEnY8Zg5WoveSCBVJIy0NXc6STcPXc4szVdL5p+s+5a8klQ\n" +
                "wTZXalrudSdKbomFbo3UqJS7ZqucJLIV9d/AAPq3bLkA+PUgKUi6hlXS1VywdpEi\n" +
                "z+5SkD6hC/APcc/KtbAWrQwGL0i/ij4wxgbN7jx7dj4LyMRQX3ROULsEXjDYY0mR\n" +
                "jGfLbgfxH1Bnef2WK2p0uNGOAUoZLDBM7pEO8RJkX/VGgoNZexiPmm8+r3ptu/HC\n" +
                "w+cZ6e+H9Esvsi4iE1YhkN1jbCwq8cMlw+mPnl7CdWit+OEFvFebQub1mz1xeO5g\n" +
                "6EAwImE3D5FuguRgxhSutfYiaPigN4GvvV9Z4BQbLOFvmVcr3AmeZMYOWOXOL8H6\n" +
                "9wJwYjKiPcJ2PqvA5aLUXDBY5rdUHf5kKL39wPYqHkPKY8BV/cqqxoc6qf6rS1zs\n" +
                "uf7hRHdfTtMhFSVsrmlPW7tT8N1bBZcHU3spkgqGAnr0cGxPuEDRXalG7SeT2Gng\n" +
                "56NyLav3XewWLbY1uqcl2A==\n" +
                "-----END ENCRYPTED PRIVATE KEY-----\n" +
                "Bag Attributes\n" +
                "    friendlyName: 1\n" +
                "    localKeyID: 54 69 6D 65 20 31 36 35 34 32 37 38 30 37 32 35 36 35\n" +
                "subject=C = US, ST = California, L = San Francisco, O = BadSSL, CN = BadSSL Client Certificate\n" +
                "\n" +
                "issuer=C = US, ST = California, L = San Francisco, O = BadSSL, CN = BadSSL Client Root Certificate Authority\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIEnTCCAoWgAwIBAgIJAPf5Tl8wfbrGMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n" +
                "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\n" +
                "c2NvMQ8wDQYDVQQKDAZCYWRTU0wxMTAvBgNVBAMMKEJhZFNTTCBDbGllbnQgUm9v\n" +
                "dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwNTE3MjExNTI0WhcNMjQwNTE2\n" +
                "MjExNTI0WjBvMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG\n" +
                "A1UEBwwNU2FuIEZyYW5jaXNjbzEPMA0GA1UECgwGQmFkU1NMMSIwIAYDVQQDDBlC\n" +
                "YWRTU0wgQ2xpZW50IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAxzdfEeseTs/rukjly6MSLHM+Rh0enA3Ai4Mj2sdl31x3SbPoen08\n" +
                "utVhjPmlxIUdkiMG4+ffe7N+JtDLG75CaxZp9CxytX7kywooRBJsRnQhmQPca8MR\n" +
                "WAJBIz+w/L+3AFkTIqWBfyT+1VO8TVKPkEpGdLDovZOmzZAASi9/sj+j6gM7AaCi\n" +
                "DeZTf2ES66abA5pOp60Q6OEdwg/vCUJfarhKDpi9tj3P6qToy9Y4DiBUhOct4MG8\n" +
                "w5XwmKAC+Vfm8tb7tMiUoU0yvKKOcL6YXBXxB2kPcOYxYNobXavfVBEdwSrjQ7i/\n" +
                "s3o6hkGQlm9F7JPEuVgbl/Jdwa64OYIqjQIDAQABoy0wKzAJBgNVHRMEAjAAMBEG\n" +
                "CWCGSAGG+EIBAQQEAwIHgDALBgNVHQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggIB\n" +
                "AFI0ykO8lSHF+h29DDuUP9bAlq4+e2GGptqUgM1KEyznEX0TrwvGY6lUuE35yT8e\n" +
                "DXTu28m/BHtIbhiTzyw86b81SOADNB4RbDDyWkpJ9dVULWl5yaO8pXPqQwqsvHkJ\n" +
                "EhRAQxaVxWXxZ/BssTNg9aEjaOZHlFLvRIWFkptUumGqRcEPDThqSvBHnc+zfhzh\n" +
                "RX6zU1R47ZZ9iWaGSfbN3jrfaYijQR99YGPBbLP4oPAbX5TZohnuFWgGT1Ac9IPx\n" +
                "nxNk20egzFsZ9ov2sr+5ORbZ5hkPzsIQFepYBlgMBHpaK66h8z9uL5xWDHyFwn/Q\n" +
                "F/urxB1C+/xLlv88MNLWna4JJSy2zENR30s+ePLYvDS5gW3yOjgSTWQlMuioi+Vb\n" +
                "JDqepWcpPDRXNMCysm6AtZYOaX/74PA2mC2T/RwvKDDJMZs6P0i7/eiDQFkFZHQ1\n" +
                "114XsW9aq2Mkj9BRWMgsq6iEqkSyEwlRJjtuNX2FQUUkVKmSf4/W6SADBkVk1ljz\n" +
                "0X4BfhYLReG5oeMsQ/8cmqrkx4LLgIbXPxcsljGTG9RBZCTANm4Uue3r2m1IUh8x\n" +
                "wRHAaXHgBJcRT6TG/Dppk7kCCuDSa56IDmka4P0XN4AB9NAnwwH0ZMX8RMrX6XVV\n" +
                "vmH9XXzuRx1b9hXYXgDdI7P6lfRheQRqtoKXbKu+eMGN\n" +
                "-----END CERTIFICATE-----\n";

        String trustMaterial =
                "Bag Attributes\n" +
                "    friendlyName: digicert global root ca\n" +
                "    2.16.840.1.113894.746875.1.1: <Unsupported tag 6>\n" +
                "subject=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA\n" +
                "\n" +
                "issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n" +
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n" +
                "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n" +
                "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n" +
                "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n" +
                "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n" +
                "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n" +
                "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n" +
                "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n" +
                "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n" +
                "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n" +
                "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n" +
                "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n" +
                "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n" +
                "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n" +
                "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n" +
                "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n" +
                "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n" +
                "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\n" +
                "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n" +
                "-----END CERTIFICATE-----\n" +
                "Bag Attributes\n" +
                "    friendlyName: cn=*.badssl.com\n" +
                "    2.16.840.1.113894.746875.1.1: <Unsupported tag 6>\n" +
                "subject=CN = *.badssl.com\n" +
                "\n" +
                "issuer=C = US, O = Let's Encrypt, CN = R3\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIFKjCCBBKgAwIBAgISBLdWAVlGEKjYNhfIBsL5jSpGMA0GCSqGSIb3DQEBCwUA\n" +
                "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n" +
                "EwJSMzAeFw0yMjA1MTcxNDA3NTZaFw0yMjA4MTUxNDA3NTVaMBcxFTATBgNVBAMM\n" +
                "DCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXg\n" +
                "KuOWDH6Zia5mubfBCvQLAw9pT0h60BNK0lOSf7IijkIBuPkZowKKcPrONiMbmZ9T\n" +
                "3My9RI8pL2m1db7JTCzuKnH7pitMBBEfKluKV1JwCedDHqt6E5X5jZ37s4GeCtsC\n" +
                "/5VxnvYat9oPF0i6cQK7ehclONv8RE766NBzRQhEIvMYrRElEknlnbjLvKe+LWc0\n" +
                "5qkWhuhrm0I1lN1gcFUXW/VQJLcBddcGmSJ5YoCHC8lqKRjGtFiziiYAMC9H3AcM\n" +
                "zyZ/ZSDC62G/lW1pWze4FpE0P8xeHtI5r2xNOYQRvS547vZ8LIdHD0rieuQTWYCL\n" +
                "aNA19OubHoavxa/CkJECAwEAAaOCAlMwggJPMA4GA1UdDwEB/wQEAwIFoDAdBgNV\n" +
                "HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4E\n" +
                "FgQUSwI65UG7O3Md4vv0BtGNOd8gOcwwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA\n" +
                "5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMu\n" +
                "by5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8w\n" +
                "IwYDVR0RBBwwGoIMKi5iYWRzc2wuY29tggpiYWRzc2wuY29tMEwGA1UdIARFMEMw\n" +
                "CAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9j\n" +
                "cHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYA36Ve\n" +
                "q2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnMAAAGA0o+7YgAABAMARzBFAiEA\n" +
                "2jT4gYW1nJP2/303vlyQV9JtLC/iJQQ24Cl8JIqQ2SUCIAQrwgTeQH/XWDbvgwma\n" +
                "A9yiih/bxG1OMQCZ6w3kEGQCAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy\n" +
                "/HD+bUcAAAGA0o+9oAAABAMARzBFAiEA2x9TJcM7vUP7m+yvb63EXc4psNUc5Z8E\n" +
                "QZG1XreKCyQCIFFiZUPzJK2apdDUkNJxCfyX3MLElzAY0mhdJIgPA8s9MA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQBOBUMPwmdvh1dWrTBCtYgD5fZ3AVOx2qPdsbz7jPE/2Z4u\n" +
                "wLDMopnK/9gg8SRdqi1TrHNHX8HSOrv+t4/WriA4Pi7gt+9VSTNrSLA+ZTqi/C3N\n" +
                "xncB1u+nr7vIxiDrA9huYusuDZuymb8As3U/Z1JMh0izAXm+pul65uyNy/sv8lbk\n" +
                "JlMUpsURfq5cFYt6Wh2ZG0Hjw0dJozSNg0DLRNSEFW8OByLLIWxHW/ThxmlZ7pXG\n" +
                "W8hUUECL+BzGadV2pbwrWK0wrVse0mCfCrGqlWheMl09A3+TIVKkn8OiZw3j0vMV\n" +
                "L+dajOLJK044rqFASqXqv5uYdLG5jx+Q2s6J9QS3\n" +
                "-----END CERTIFICATE-----\n" +
                "Bag Attributes\n" +
                "    friendlyName: cn=isrg root x1,o=internet security research group,c=us\n" +
                "    2.16.840.1.113894.746875.1.1: <Unsupported tag 6>\n" +
                "subject=C = US, O = Internet Security Research Group, CN = ISRG Root X1\n" +
                "\n" +
                "issuer=O = Digital Signature Trust Co., CN = DST Root CA X3\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/\n" +
                "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
                "DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow\n" +
                "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n" +
                "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC\n" +
                "ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL\n" +
                "wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D\n" +
                "LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK\n" +
                "4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5\n" +
                "bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y\n" +
                "sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ\n" +
                "Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4\n" +
                "FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc\n" +
                "SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql\n" +
                "PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND\n" +
                "TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\n" +
                "SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1\n" +
                "c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx\n" +
                "+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB\n" +
                "ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu\n" +
                "b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E\n" +
                "U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu\n" +
                "MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC\n" +
                "5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW\n" +
                "9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG\n" +
                "WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O\n" +
                "he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC\n" +
                "Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5\n" +
                "-----END CERTIFICATE-----\n" +
                "Bag Attributes\n" +
                "    friendlyName: cn=r3,o=let's encrypt,c=us\n" +
                "    2.16.840.1.113894.746875.1.1: <Unsupported tag 6>\n" +
                "subject=C = US, O = Let's Encrypt, CN = R3\n" +
                "\n" +
                "issuer=C = US, O = Internet Security Research Group, CN = ISRG Root X1\n" +
                "\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\n" +
                "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n" +
                "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\n" +
                "WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\n" +
                "RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\n" +
                "R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\n" +
                "sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\n" +
                "NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\n" +
                "Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n" +
                "/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\n" +
                "AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\n" +
                "Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\n" +
                "FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\n" +
                "AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\n" +
                "Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\n" +
                "gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\n" +
                "PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\n" +
                "ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\n" +
                "CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\n" +
                "lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\n" +
                "avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\n" +
                "yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\n" +
                "yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\n" +
                "hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\n" +
                "HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\n" +
                "MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\n" +
                "nLRbwHOoq7hHwg==\n" +
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
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com]");
        }
    }
}
