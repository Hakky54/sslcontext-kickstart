package nl.altindag.sslcontext;

import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.ApacheSslContextUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forRoot();

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        LayeredConnectionSocketFactory socketFactory = ApacheSslContextUtils.toLayeredConnectionSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpGet request = new HttpGet("https://client.badssl.com/");
        HttpResponse response = httpClient.execute(request);

        int statusCode = response.getStatusLine().getStatusCode();

        assertThat(statusCode).isEqualTo(200);
        assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
    }

}
