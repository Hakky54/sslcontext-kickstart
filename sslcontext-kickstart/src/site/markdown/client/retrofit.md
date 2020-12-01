## Retrofit - Example SSL Client Configuration

```java
import nl.altindag.ssl.SSLFactory;
import okhttp3.OkHttpClient;
import retrofit2.Retrofit;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow())
                .hostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        Retrofit retrofit = new Retrofit.Builder()
                .client(okHttpClient)
                .baseUrl("https://localhost:8443/api/hello")
                .build();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.