## Async Http Client - Example SSL Client Configuration

```java
import dispatch.Http;
import io.netty.handler.ssl.SslContext;
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.NettySslContextUtils;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;
import org.asynchttpclient.Dsl;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        DefaultAsyncHttpClientConfig.Builder clientConfigBuilder = Http.defaultClientBuilder()
                .setSslContext(sslContext);

        AsyncHttpClient httpClient = Dsl.asyncHttpClient(clientConfigBuilder);
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.