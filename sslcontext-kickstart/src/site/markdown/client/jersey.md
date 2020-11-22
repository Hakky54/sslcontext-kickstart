## Jersey Client - Example SSL Client Configuration

```java
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        Client client = ClientBuilder.newBuilder()
                .sslContext(sslFactory.getSslContext())
                .hostnameVerifier(sslFactory.getHostnameVerifier())
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.