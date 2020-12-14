package ssl;

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.SSLFactory;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleResponseConsumer;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.nio.support.BasicRequestProducer;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import util.Apache5SslUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

class SSLFactoryIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactoryIT.class);

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache5SslUtils.toSocketFactory(sslFactory);
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();

        HttpGet request = new HttpGet("https://client.badssl.com/");
        HttpResponse response = httpClient.execute(request);

        int statusCode = response.getCode();

        if (statusCode == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    void executeHttpsRequestWithMutualAuthenticationForAsyncClient() throws IOException, URISyntaxException, InterruptedException, ExecutionException, TimeoutException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        PoolingAsyncClientConnectionManager connectionManager = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(Apache5SslUtils.toTlsStrategy(sslFactory))
                .build();

        CloseableHttpAsyncClient httpAsyncClient = HttpAsyncClients.custom()
                .setConnectionManager(connectionManager)
                .build();

        httpAsyncClient.start();

        SimpleHttpResponse response = httpAsyncClient.execute(
                new BasicRequestProducer(Method.GET, new URI("https://client.badssl.com/")),
                SimpleResponseConsumer.create(), null, null, null)
                .get(10, TimeUnit.SECONDS);


        int statusCode = response.getCode();

        if (statusCode == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

}
