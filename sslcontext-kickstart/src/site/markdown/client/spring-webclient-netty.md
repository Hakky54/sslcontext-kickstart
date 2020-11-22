## Spring WebFlux WebClient with Netty - Example SSL Client Configuration

```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.NettySslContextUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create().secure(sslSpec -> sslSpec.sslContext(sslContext));
        
        WebClient webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.