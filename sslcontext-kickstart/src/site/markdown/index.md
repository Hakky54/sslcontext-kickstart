## Introduction
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

import nl.altindag.ssl.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
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

The SSLFactory provides different kinds of returnable values, see below for all the options:
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.model.KeyStoreHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore.p12", "secret".toCharArray(), "PKCS12")
                .withTrustMaterial("truststore.p12", "secret".toCharArray(), "PKCS12")
                .build();

        SSLContext sslContext = sslFactory.getSslContext();
        HostnameVerifier hostnameVerifier = sslFactory.getHostnameVerifier();
        Optional<X509ExtendedKeyManager> keyManager = sslFactory.getKeyManager();
        Optional<X509ExtendedTrustManager> trustManager = sslFactory.getTrustManager();
        List<X509Certificate> trustedCertificates = sslFactory.getTrustedCertificates();
        List<KeyStoreHolder> identities = sslFactory.getIdentities();
        List<KeyStoreHolder> trustStores = sslFactory.getTrustStores();
        SSLSocketFactory sslSocketFactory = sslFactory.getSslSocketFactory();
        SSLServerSocketFactory sslServerSocketFactory = sslFactory.getSslServerSocketFactory();
        SSLEngine sslEngine = sslFactory.getSslEngine(host, port);
        SSLParameters sslParameters = sslFactory.getSslParameters();
        List<String> ciphers = sslFactory.getCiphers();
        List<String> protocols = sslFactory.getProtocols();
    }

}
```
### Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration

**Java**

* [Apache HttpClient](https://hc.apache.org/httpcomponents-client-4.5.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L74) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpClientService.java)
* [Apache HttpAsyncClient](https://hc.apache.org/httpcomponents-asyncclient-4.1.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L86) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpAsyncClientService.java)
* [Apache 5 HttpClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L101) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpClientService.java)
* [Apache 5 HttpAsyncClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples-async.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L116) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpAsyncClientService.java)
* [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L135) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JdkHttpClientService.java)
* [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJdkHttpClientService.java)
* [Netty Reactor](https://github.com/reactor/reactor-netty) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L168) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ReactorNettyService.java)
* [Jetty Reactive HttpClient](https://github.com/jetty-project/jetty-reactive-httpclient) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L179) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JettyReactiveHttpClientService.java)
* [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L147) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringRestTemplateService.java)
* [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L189) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L196) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [OkHttp](https://github.com/square/okhttp) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L155) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OkHttpClientService.java)
* [Jersey Client](https://eclipse-ee4j.github.io/jersey/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L203) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JerseyClientService.java)
* Old Jersey Client -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L215) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJerseyClientService.java)
* [Apache CXF JAX-RS](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L231) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFJaxRsClientService.java)
* [Apache CXF using ConduitConfigurer](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L244) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFWebClientService.java)
* [Google HttpClient](https://github.com/googleapis/google-http-java-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L261) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/GoogleHttpClientService.java)
* [Unirest](https://github.com/Kong/unirest-java) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L273) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/UnirestService.java)
* [Retrofit](https://github.com/square/retrofit) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L285) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RetrofitService.java)
* [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L325) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AsyncHttpClientService.java)
* [Feign](https://github.com/OpenFeign/feign) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L339) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FeignService.java)
* [Methanol](https://github.com/mizosoft/methanol) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L349) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/MethanolService.java)
* [Vertx Webclient](https://github.com/vert-x3/vertx-web) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L361) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/VertxWebClientService.java)
* [gRPC](https://grpc.io/) -> [Client/Server Configuration & Example request](https://github.com/Hakky54/java-tutorials)

**Kotlin**

* [Fuel](https://github.com/kittinunf/fuel) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FuelService.kt)
* [Http4k with Apache 4](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache4HttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Async Apache 4](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache4AsyncHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kAsyncClientService.kt)
* [Http4k with Apache 5](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache5HttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Async Apache 5](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache5AsyncHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kAsyncClientService.kt)
* [Http4k with Java Net](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kJavaHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Jetty](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kJettyHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with OkHttp](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Kohttp](https://github.com/rybalkinsd/kohttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KohttpService.kt)
* [Ktor with Android engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorAndroidHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Apache engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorApacheHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with CIO (Coroutine-based I/O) engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorCIOHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Okhttp engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)

**Scala**

* [Twitter Finagle](https://github.com/twitter/finagle) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L294) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FinagleHttpClientService.java)
* [Twitter Finagle Featherbed](https://github.com/finagle/featherbed) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/d78e4e81b8b775d3ff09c11b0a7c1532a741199e/client/src/main/java/nl/altindag/client/service/FeatherbedRequestService.scala#L19)
* [Akka Http Client](https://github.com/akka/akka-http) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/cad26082c836ab14eaf3f836de9fff026aadf698/client/src/main/java/nl/altindag/client/ClientConfig.java#L314) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AkkaHttpClientService.java)
* [Dispatch Reboot](https://github.com/dispatch/reboot) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/DispatchRebootService.scala)
* [ScalaJ / Simplified Http Client](https://github.com/scalaj/scalaj-http) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ScalaJHttpClientService.scala)
* [Sttp](https://github.com/softwaremill/sttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SttpHttpClientService.scala)
* [Requests-Scala](https://github.com/lihaoyi/requests-scala) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RequestsScalaService.scala)
* [Http4s Blaze Client](https://github.com/http4s/http4s) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sBlazeClientService.scala) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sService.scala)
* [Http4s Java Net Client](https://github.com/http4s/http4s) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sJavaNetClientService.scala) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sService.scala)

There is a github project available named [Mutual-tls-ssl](https://github.com/Hakky54/mutual-tls-ssl) which provides a tutorial containing steps for setting up these four scenarios:

* No security
* One way authentication
* Two way authentication
* Two way authentication with trusting the Certificate Authority

It will also explain how to create KeyStores, Certificates, Certificate Signing Requests and how to implement it.