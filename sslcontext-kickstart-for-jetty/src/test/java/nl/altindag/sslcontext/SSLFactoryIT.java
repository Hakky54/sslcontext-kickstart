package nl.altindag.sslcontext;

import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.JettySslContextUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws Exception {
        LogCaptor logCaptor = LogCaptor.forRoot();

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);

        HttpClient httpClient = new HttpClient(sslContextFactory);
        httpClient.start();

        ContentResponse contentResponse = httpClient.newRequest("https://client.badssl.com/")
                .method(HttpMethod.GET)
                .send();

        httpClient.stop();

        assertThat(contentResponse.getStatus()).isEqualTo(200);
        assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
    }

}
