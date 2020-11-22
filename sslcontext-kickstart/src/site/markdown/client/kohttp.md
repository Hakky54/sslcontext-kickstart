## KoHttp - Example SSL Client Configuration

```kotlin
import io.github.rybalkinsd.kohttp.client.client
import io.github.rybalkinsd.kohttp.configuration.SslConfig
import nl.altindag.sslcontext.SSLFactory

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = client {
            sslConfig = SslConfig().apply {
                sslSocketFactory = sslFactory.sslSocketFactory
                trustManager = sslFactory.trustManager.orElseThrow()
                hostnameVerifier = sslFactory.hostnameVerifier
            }
        }
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.