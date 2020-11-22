## JDK HttpClient - Example SSL Client Configuration

```java
import nl.altindag.sslcontext.SSLFactory;

import java.net.http.HttpClient;

public class App {

    public static void main(String[] args) throws Exception{
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        HttpClient.newBuilder()
                .sslParameters(sslFactory.getSslParameters())
                .sslContext(sslFactory.getSslContext())
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.