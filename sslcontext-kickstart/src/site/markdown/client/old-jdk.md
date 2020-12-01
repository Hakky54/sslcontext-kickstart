## Old JDK HttpClient - Example SSL Client Configuration

```java
import nl.altindag.ssl.SSLFactory;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        String url = "https://localhost:8443/api/hello";
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.