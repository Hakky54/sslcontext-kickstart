## OkHttp - Example SSL Client Configuration

```java
import nl.altindag.sslcontext.SSLFactory;
import okhttp3.OkHttpClient;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        OkHttpClient httpClient = new OkHttpClient.Builder()
                .sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow())
                .hostnameVerifier(sslFactory.getHostnameVerifier())
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.