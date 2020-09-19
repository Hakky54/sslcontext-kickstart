package nl.altindag.sslcontext;

import io.netty.handler.ssl.SslContext;
import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.NettySslContextUtils;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.util.function.Tuple2;

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

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create().secure(sslSpec -> sslSpec.sslContext(sslContext));

        Integer statusCode = httpClient.get()
                .uri("https://client.badssl.com/")
                .responseSingle((response, body) -> Mono.zip(body.asString(), Mono.just(response.status().code())))
                .map(Tuple2::getT2)
                .block();

        assertThat(statusCode).isEqualTo(200);
        assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
    }

}
