## ScalaJ - Example SSL Client Configuration

```scala
import javax.net.ssl.HttpsURLConnection
import nl.altindag.ssl.SSLFactory
import scalaj.http.Http

object App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()

        val httpOption = {
            case httpsURLConnection: HttpsURLConnection =>
              httpsURLConnection.setHostnameVerifier(sslFactory.getHostnameVerifier)
              httpsURLConnection.setSSLSocketFactory(sslFactory.getSslSocketFactory)
            case _ =>
        }

        val response = Http("https://localhost:8443/api/hello")
                .method("GET")
                .option(httpOption)
                .asString
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.