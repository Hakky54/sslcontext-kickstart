## Http4k with Jetty Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.JettySslUtils
import org.eclipse.jetty.client.HttpClient
import org.http4k.client.JettyClient

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = JettyClient(
                client = HttpClient(JettySslUtils.forClient(sslFactory))
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.