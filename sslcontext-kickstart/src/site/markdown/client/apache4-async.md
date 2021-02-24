## Apache Async HttpClient 4- Example SSL Client Configuration

```java
import nl.altindag.ssl.SSLFactory;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        CloseableHttpAsyncClient client = HttpAsyncClients.custom()
                .setSSLContext(sslFactory.getSslContext())
                .setSSLHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        client.start();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.