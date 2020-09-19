package nl.altindag.sslcontext;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;

import static nl.altindag.sslcontext.TestConstants.KEYSTORE_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;

class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forRoot();

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(KEYSTORE_LOCATION + "badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KEYSTORE_LOCATION + "badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://client.badssl.com/").openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslContext().getSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        assertThat(connection.getResponseCode()).isEqualTo(200);
        assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
    }

}
