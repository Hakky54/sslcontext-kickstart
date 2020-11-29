## Ktor with Android Engine - Example SSL Client Configuration

```kotlin
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import nl.altindag.sslcontext.SSLFactory

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val httpClient = HttpClient(Android) {
            engine {
                sslManager = { httpsURLConnection ->
                    httpsURLConnection.hostnameVerifier = sslFactory.hostnameVerifier
                    httpsURLConnection.sslSocketFactory = sslFactory.sslSocketFactory
                }
            }
        }
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.