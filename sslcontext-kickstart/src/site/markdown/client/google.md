## Google HttpClient - Example SSL Client Configuration

```java
import com.google.api.client.http.javanet.NetHttpTransport;
import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        NetHttpTransport httpTransport = new NetHttpTransport.Builder()
                .setSslSocketFactory(sslFactory.getSslSocketFactory())
                .setHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.