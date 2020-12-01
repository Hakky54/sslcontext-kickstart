## STTP - Example SSL Client Configuration

```scala
import java.net.URI

import javax.net.ssl.HttpsURLConnection
import nl.altindag.ssl.SSLFactory
import sttp.client.{HttpURLConnectionBackend, basicRequest}
import sttp.model.Uri

object App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()

        val sttpBackend = HttpURLConnectionBackend(customizeConnection = {
            case httpsConnection: HttpsURLConnection =>
              httpsConnection.setHostnameVerifier(sslFactory.getHostnameVerifier)
              httpsConnection.setSSLSocketFactory(sslFactory.getSslSocketFactory)
            case _ =>
        })

        val request = basicRequest.get(uri = Uri(javaUri = URI.create("https://localhost:8443/api/hello")))
        val response = request.send(sttpBackend)
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.