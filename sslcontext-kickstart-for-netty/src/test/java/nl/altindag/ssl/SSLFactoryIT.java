package nl.altindag.ssl;

import io.netty.handler.ssl.SslContext;
import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.NettySslContextUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.util.function.Tuple2;

import java.io.IOException;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

class SSLFactoryIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactoryIT.class);

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

        if (Objects.requireNonNull(statusCode) == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

}
