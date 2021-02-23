## Apache CXF Jax RS HttpClient - Example SSL Client Configuration

```java
import nl.altindag.ssl.SSLFactory;
import org.apache.cxf.jaxrs.client.spec.ClientBuilderImpl;

import javax.ws.rs.client.Client;

class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        Client client = new ClientBuilderImpl()
                .sslContext(sslFactory.getSslContext())
                .hostnameVerifier(sslFactory.getHostnameVerifier())
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.