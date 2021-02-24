## Http4k with Java Http Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import org.http4k.client.JavaHttpClient
import java.net.http.HttpClient

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = JavaHttpClient(
                httpClient = HttpClient.newBuilder()
                        .sslParameters(sslFactory.sslParameters)
                        .sslContext(sslFactory.sslContext)
                        .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.