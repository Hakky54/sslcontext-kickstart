## SSLContext Kickstart
SSLContext Kickstart is a high level library for configuring a http client to communicate over SSL/TLS for one way authentication or two way authentication.

Below is a quick start; more detailed usage information is available [here.](./usage.html) See the [JavaDocs](./apidocs/index.html) for full documentation and the [Test Source](./xref-test/index.html) for complete examples of usage.

Details on how to depend on this library in your favourite build tool can be found [here](./dependency-info.html).

### Getting Started
#### Basic example with Apache Http Client
```java
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslFactory.getSslContext())
                .setSSLHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        HttpGet request = new HttpGet("https://api.chucknorris.io/jokes/random");
        HttpResponse response = httpClient.execute(request);
    }

}
```

#### Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration.

* [Apache HttpClient](https://github.com/apache/httpcomponents-client)
* [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html)
* [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html)
* [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html)
* [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html)
* [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html)
* [OkHttp](https://github.com/square/okhttp)
* [Jersey Client](https://eclipse-ee4j.github.io/jersey/)
* Old Jersey Client
* [Google HttpClient](https://github.com/googleapis/google-http-java-client)
* [Unirest](https://github.com/Kong/unirest-java)
* [Retrofit](https://github.com/square/retrofit)
* [Twitter Finagle Http Client](https://github.com/twitter/finagle)
* [Akka Http Client](https://github.com/akka/akka-http)
* [Dispatch Reboot Http Client](https://github.com/dispatch/reboot)
* [Async Http Client](https://github.com/AsyncHttpClient/async-http-client)
* [ScalaJ Http Client](https://github.com/scalaj/scalaj-http)  