## Vertx - Example SSL Client Configuration

```java
import io.vertx.core.Vertx;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.TrustOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import nl.altindag.ssl.SSLFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        WebClientOptions clientOptions = new WebClientOptions();
        clientOptions.setSsl(true);

        sslFactory.getKeyManager()
                .map(KeyCertOptions::wrap)
                .ifPresent(clientOptions::setKeyCertOptions);

        sslFactory.getTrustManager()
                .map(TrustOptions::wrap)
                .ifPresent(clientOptions::setTrustOptions);

        sslFactory.getCiphers().forEach(clientOptions::addEnabledCipherSuite);
        sslFactory.getProtocols().forEach(clientOptions::addEnabledSecureTransportProtocol);

        WebClient webClient = WebClient.create(Vertx.vertx(), clientOptions);
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.