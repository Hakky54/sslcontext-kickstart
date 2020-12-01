## Requests-Scala - Example SSL Client Configuration

```scala
import nl.altindag.ssl.SSLFactory

object App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()

        val response = requests.get(
                "https://localhost:8443/api/hello",
                sslContext = sslFactory.getSslContext
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.