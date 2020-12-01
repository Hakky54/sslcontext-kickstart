## Feign - Example SSL Client Configuration

```java
import feign.Client;
import feign.Feign;
import nl.altindag.ssl.SSLFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        Feign.Builder client = Feign.builder()
                .client(new Client.Default(sslFactory.getSslSocketFactory(), sslFactory.getHostnameVerifier()));
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.