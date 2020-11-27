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

import nl.altindag.sslcontext.SSLFactory;

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
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.model.KeyStoreHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
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
        SSLParameters sslParameters = sslFactory.getSslParameters();
        List<String> ciphers = sslFactory.getCiphers();
        List<String> protocols = sslFactory.getProtocols();
    }

}
```
### Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration

**Java**

* [Apache HttpClient](https://github.com/apache/httpcomponents-client) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L86) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpClientService.java)
* [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L98) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JdkHttpClientService.java)
* [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJdkHttpClientService.java)
* [Netty Reactor](https://github.com/reactor/reactor-netty) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L131) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ReactorNettyService.java)
* [Jetty Reactive HttpClient](https://github.com/jetty-project/jetty-reactive-httpclient) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L142) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JettyReactiveHttpClientService.java)
* [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L110) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringRestTemplateService.java)
* [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L152) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L159) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [OkHttp](https://github.com/square/okhttp) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L118) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OkHttpClientService.java)
* [Jersey Client](https://eclipse-ee4j.github.io/jersey/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L166) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JerseyClientService.java)
* Old Jersey Client -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L178) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJerseyClientService.java)
* [Google HttpClient](https://github.com/googleapis/google-http-java-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L190) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/GoogleHttpClientService.java)
* [Unirest](https://github.com/Kong/unirest-java) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L202) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/UnirestService.java)
* [Retrofit](https://github.com/square/retrofit) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L212) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RetrofitService.java)
* [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L257) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AsyncHttpClientService.java)
* [Feign](https://github.com/OpenFeign/feign) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/4329bb91bbe6862e413423c71dfabccde6bdefbf/client/src/main/java/nl/altindag/client/ClientConfig.java#L243) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FeignService.java)
* [Methanol](https://github.com/mizosoft/methanol) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/4329bb91bbe6862e413423c71dfabccde6bdefbf/client/src/main/java/nl/altindag/client/ClientConfig.java#L253) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/MethanolService.java)

**Kotlin**

* [Fuel](https://github.com/kittinunf/fuel) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FuelService.kt)
* [Kohttp](https://github.com/rybalkinsd/kohttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KohttpService.kt)
* [Ktor Android](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorAndroidHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor Apache](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorApacheHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor Okhttp](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)

**Scala**

* [Twitter Finagle](https://github.com/twitter/finagle) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L221) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FinagleHttpClientService.java)
* [Twitter Finagle Featherbed](https://github.com/finagle/featherbed) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FeatherbedRequestService.scala)
* [Akka Http Client](https://github.com/akka/akka-http) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/941f2f462221aa321d64be060c63a9fc678f689d/client/src/main/java/nl/altindag/client/ClientConfig.java#L241) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AkkaHttpClientService.java)
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