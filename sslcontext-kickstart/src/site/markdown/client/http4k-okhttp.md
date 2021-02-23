## Http4k with OkHttp Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import okhttp3.OkHttpClient
import org.http4k.client.OkHttp

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = OkHttp(
                client = OkHttpClient().newBuilder()
                        .sslSocketFactory(sslFactory.sslSocketFactory, sslFactory.trustManager.orElseThrow())
                        .hostnameVerifier(sslFactory.hostnameVerifier)
                        .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.