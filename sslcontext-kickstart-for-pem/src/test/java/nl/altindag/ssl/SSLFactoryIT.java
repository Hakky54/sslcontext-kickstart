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
                "    localKeyID: 77 23 D2 3A C0 2C 87 E2 AD 98 3F 06 68 F2 54 33 B6 05 0E FE \n" +
                "subject=/C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Client Certificate\n" +
                "issuer=/C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Client Root Certificate Authority\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIEnTCCAoWgAwIBAgIJAPYAapdmy98xMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n" +
                "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\n" +
                "c2NvMQ8wDQYDVQQKDAZCYWRTU0wxMTAvBgNVBAMMKEJhZFNTTCBDbGllbnQgUm9v\n" +
                "dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjExMjA0MDAwODE5WhcNMjMxMjA0\n" +
                "MDAwODE5WjBvMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG\n" +
                "A1UEBwwNU2FuIEZyYW5jaXNjbzEPMA0GA1UECgwGQmFkU1NMMSIwIAYDVQQDDBlC\n" +
                "YWRTU0wgQ2xpZW50IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAxzdfEeseTs/rukjly6MSLHM+Rh0enA3Ai4Mj2sdl31x3SbPoen08\n" +
                "utVhjPmlxIUdkiMG4+ffe7N+JtDLG75CaxZp9CxytX7kywooRBJsRnQhmQPca8MR\n" +
                "WAJBIz+w/L+3AFkTIqWBfyT+1VO8TVKPkEpGdLDovZOmzZAASi9/sj+j6gM7AaCi\n" +
                "DeZTf2ES66abA5pOp60Q6OEdwg/vCUJfarhKDpi9tj3P6qToy9Y4DiBUhOct4MG8\n" +
                "w5XwmKAC+Vfm8tb7tMiUoU0yvKKOcL6YXBXxB2kPcOYxYNobXavfVBEdwSrjQ7i/\n" +
                "s3o6hkGQlm9F7JPEuVgbl/Jdwa64OYIqjQIDAQABoy0wKzAJBgNVHRMEAjAAMBEG\n" +
                "CWCGSAGG+EIBAQQEAwIHgDALBgNVHQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggIB\n" +
                "ABlLNovFvSrULgLvJmKX/boSWQOhWE0HDX6bVKyTs48gf7y3DXSOD+bHkBNHL0he\n" +
                "m4HRFSarj+x389oiPEti5i12Ng9OLLHwSHK+7AfnrkhLHA8ML3NWw0GBr5DgdsIv\n" +
                "7MJdGIrXPQwTN5j++ICyY588TfGHH8vU5qb5PrSqClLZSSHU05FTr/Dc1B8hKjjl\n" +
                "d/FKOidLo1YDLFUjaB9x1mZPUic/C489lyPfWqPqoMRd5i/XShST5FPvfGuKRd5q\n" +
                "XKDkrn+GaQ/4iDDdCgekDCCPhOwuulavNxBDjShwZt1TeUrZNSM3U4GeZfyrVBIu\n" +
                "Tr+gBK4IkD9d/vP7sa2NQszF0wRQt3m1wvSWxPz91eH+MQU1dNPzg1hnQgKKIrUC\n" +
                "NTab/CAmSQfKC1thR15sPg5bE0kwJd1AJ1AqTrYxI0VITUV8Gka3tSAp3aKZ2LBg\n" +
                "gYHLI2Rv9jXe5Yx5Dckf3l+YSFp/3dSDkFOgEuZm2FfZl4vNBR+coohpB9+2jRWL\n" +
                "K+4fIkCJba+Y2cEd5usJE18MTH9FU/JKDwzC+eO9SNLFUw3zGUsSwgZsBHP6kiQN\n" +
                "suia9q4M5f+68kzM4+0NU8HwwyzZEtmTBhktKHijExixdvjlMAZ8hAOsFifsevI0\n" +
                "02dUYvtxoHaeXh4jpYHVNnsIf/74uLagiPHtVf7+9UZV\n" +
                "-----END CERTIFICATE-----\n" +
                "Bag Attributes\n" +
                "    localKeyID: 77 23 D2 3A C0 2C 87 E2 AD 98 3F 06 68 F2 54 33 B6 05 0E FE \n" +
                "Key Attributes: <No Attributes>\n" +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI+UxRzaMlG20CAggA\n" +
                "MBQGCCqGSIb3DQMHBAgwKqY1HKSrfwSCBMjFCuZXyx8U2OJSkNdSlu9Dcp8gYzjo\n" +
                "t3qArDdw2py8dxIk90j2deYBMrO+VnvXARmqfd2IYKyGIhDE5uLf8CEzZiVDxfm9\n" +
                "6h8Tcf3Z7mLyuzcye445+jQTJ6tz9zDVlpOgHMluBBHE18c2JogBZIMsp/IvAoqQ\n" +
                "93aseno6hMUMhDJBWpd7onaCiYQ07PJ/Q3Bx/Vp/Nmoqg/5Goss4AekxGm6ZoLPA\n" +
                "VDPw4qfSSYhS2S4Hxh7rTn8a2n0bwmYc0ZEfvowlTiE0twHt149n6z/5WqUUHbY5\n" +
                "P3Lu2j+y1nEl5hpipPyZjVZ6kGC73g4XgMvErFk4I3WHq9+KBjPr6PW9JshH+sFc\n" +
                "Nn/w38rZtNaOj4dLkDb8q/WVkOinh2idRRAlMI9amYgbtqHR0aWlVBeBKFapm9Ja\n" +
                "2PE6IZIRFRaJquqydc2u/DzNOYNNFA7VL/Ao8KGVgq0dfOtK0NXDGndtVnABy6sm\n" +
                "5JR2Xl3R9CMAR0hfPBG+7+8TcKEpTbA4t+OnQ0yd2LlxuqSwcX7gzfztnkcF2N2z\n" +
                "gDc2LODrl/pO5LM/QmzPpwO86Pv4a1xTe33uSmPCv5SQZIHFiJgoGb2/0Prd8GU4\n" +
                "DUgwh/b+1E96JUZIFXnkBBJVgfTO1q6t3S+nyQFZqm2oVaQlq1LqLsfBWNrspzOy\n" +
                "BMFpiP8d715F3Dn6BuGe8cpa8z3uk2N47sfb6y+ACBiD2Ix1muw8CnzXOr1q3z7A\n" +
                "Ha9akGXUYbs33GeDRJFHGP69/2PGn19mIxd/uGcIiTuln7nWJM1Mwx2neDdCw6nk\n" +
                "p7NpUtyIbEX3Az5Tn93rkqn9QfWjwmk8DaKdhW+LXutvf7fx/l66srTF/AJDLPP3\n" +
                "llr1hsurquy3sAfAgqVwHYZADDn9V/BA64fiiX+Xqk9povRPUlM6Yr+ZC+okbIwG\n" +
                "FIJvB1qISPO2fbipdaEpaJ63rFLX8ZFScgyoT4Rimj+q2zRZHE8YPsX0lKyMrnmk\n" +
                "weSyVfmiOM0tfc8XuPgdePaTe7nz+q0w+4C6Vp/tyKsDHtpKWFjT7/zP0iF/isRp\n" +
                "stTjXMVg6/gzNcxLoWzz0GPZEdTADPUv4SFfxbuMAfiUsVdAOydpDA2IgiSLr3Ed\n" +
                "Wfx4CoLv1AWd2U4CxHGZjiEeBn5iv+qUow+k0WnV/Ireg+FAT5J6dcnljpUcp1K/\n" +
                "QEgCaqiMppl3Ws/V0xIKIgk4YoNdNLROLbX+eYqpztdZh98QTGxGen543LkZU/eH\n" +
                "kQYBmZX6/wOyP90G8lM+2XG7PX1TMTXMOwSpmq6v8cXZhjGxtOz5/4OvGVKvgLCW\n" +
                "A83tB6IUm5zGuICboFefHUnL5e7+cnYJo82yp2SpPuPQcnC2HEVppYxa99NNEPl2\n" +
                "fAPwtlTiYUeKNF8rPdx8bF4bwmY3R9z1uRIsa0jbIOMXl7lyAYyGIZDbheH7B4qO\n" +
                "FQ05hmV8XyD5Atvhg7k26GXP6izC+s6Redf+gRRlV6maisdZasCU4oEEpm/T856e\n" +
                "yqmP34nrN1DeBK3L/3riOgXBQU/nV3no+gRxWLjXkgq4RcKq+cv6qDR8gKFO+Z1f\n" +
                "ySnyvm+uj7+8zvpa3klXwbwtdsKVs1xO8SLVY3/45x8ofyFDR72RO0XIvg2KIz7a\n" +
                "U34=\n" +
                "-----END ENCRYPTED PRIVATE KEY-----\n";

        String trustMaterial =
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
