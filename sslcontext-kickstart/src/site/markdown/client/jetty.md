## Jetty Reactive HttpClient - Example SSL Client Configuration

```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.JettySslContextUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);

        HttpClient httpClient = new HttpClient(sslContextFactory);
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.