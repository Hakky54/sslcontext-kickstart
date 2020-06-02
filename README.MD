[![Actions Status](https://github.com/Hakky54/sslcontext-kickstart/workflows/Build/badge.svg)](https://github.com/Hakky54/sslcontext-kickstart/actions)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=security_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Known Vulnerabilities](https://snyk.io/test/github/Hakky54/sslcontext-kickstart/badge.svg)](https://snyk.io/test/github/Hakky54/sslcontext-kickstart)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=coverage)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/sslcontext-kickstart/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/sslcontext-kickstart/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)

# Install library with:
### Install with [Maven](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart</artifactId>
    <version>3.0.9</version>
</dependency>
```
### Install with Gradle
```groovy
implementation 'io.github.hakky54:sslcontext-kickstart:3.0.9'
```
### Install with Scala SBT
```
libraryDependencies += "io.github.hakky54" % "sslcontext-kickstart" % "3.0.9"
```
### Install with Apache Ivy
```xml
<dependency org="io.github.hakky54" name="sslcontext-kickstart" rev="3.0.9" />
```

## Table of contents
1. [Introduction](#introduction)
   - [History](#history)
   - [Acknowledgement](#acknowledgement)
   - [Advantages](#advantages)
   - [Definitions](#definitions)
2. [Usage](#usage)
   - [Example configuration](#example-configuration)
   - [Other possible configurations](#other-possible-configurations)
3. [Additional mappers for specific libraries](#additional-mappers-for-specific-libraries)
   - [Netty](#netty)
   - [Jetty](#jetty)
   - [Apache](#apache)
4. [Tested HTTP Clients](#tested-http-clients)

## Introduction
SSLContext Kickstart is a library which provides a High-Level [Factory class](#usage) for configuring a http client to communicate over SSL/TLS for one way authentication or two way authentication.

### History
As a Java developer I worked for different kinds of clients. Most of the time the application required to call other microservices within the organization or some other http servers. 
It was required to be HTTPS configured and so I began writing the code which was needed to configure the Http Client to communicate over ssl/tls. And every time I needed to write almost the same code over and over again which is in my opinion very verbose and hard to unit test.

As a developer you need to know how to properly load your file into your application and consume it as a KeyStore instance. Therefor you also need to learn how to properly create a KeyManagerFactory, TrustManagerFactory and SSLContext. 
Traditional creation of SSLContext can be rewritten if you use a Http Client which relies on libraries of Jetty or Netty and therefor it makes it even more complex.
The sslcontext-kickstart library is taking the responsibility of creating an instance of SSLContext from the provided arguments. I wanted to be as easy as possible to use to give every developer a kickstart when configuring their Http Client. So feel free to provide feedback or feature requests.
The library also provide other utilities such as [KeyStoreUtils](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/KeyStoreUtils.java), [KeyManagerUtils](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/KeyManagerUtils.java) and [TrustManagerUtils](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/TrustManagerUtils.java). See the [javadoc](https://sslcontext-kickstart.com/apidocs/index.html) for all the options.

### Acknowledgement
I would like to thank [Cody A. Ray](https://github.com/codyaray) for his contribution to the community regarding loading multiple Keystores into the SSLContext. The limitation of the JDK is to only support one keystore for the KeyManagerFactory and only one keystore for the TrustManagerFactory.
The code snippets which Cody has shared are now available within this library and can be found here: [CompositeX509KeyManager](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/keymanager/CompositeX509ExtendedKeyManager.java) and [CompositeX509TrustManager](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/trustmanager/CompositeX509ExtendedTrustManager.java) 

The original article can be found here: [Codyaray - Java SSL with Multiple KeyStores](http://codyaray.com/2013/04/java-ssl-with-multiple-keystores).

### Advantages:
* No need for low-level SSLContext configuration anymore
* No knowledge needed about SSLContext, TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
* Above classes will all be created with just providing an identity and a trustStore
* Load multiple identities/trustStores/keyManagers/trustManagers

### Definitions
* Identity: A KeyStore which holds the key pair also known as private and public key
* TrustStore: A KeyStore containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
* One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
* Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

## Usage
### Example configuration
Example configuration with apache http client, or see here for other clients: [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java)
```java
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException, JSONException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslFactory.getSslContext())
                .setSSLHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        HttpGet request = new HttpGet("https://api.chucknorris.io/jokes/random");

        HttpResponse response = httpClient.execute(request);
        String chuckNorrisJoke = new JSONObject(EntityUtils.toString(response.getEntity())).getString("value");

        System.out.println(String.format("Received the following status code: %d", response.getStatusLine().getStatusCode()));
        System.out.println(String.format("Received the following joke: %s", chuckNorrisJoke));
    }

}
```
Response:
```text
Received the following status code: 200
Received the following joke: If a black cat crosses your path, you have bad luck. If Chuck Norris crosses your path, it was nice knowing you.
```

The SSLFactory provides other useful options, see below for all the returnable values:
```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.model.KeyStoreHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentity("keystore.p12", "secret".toCharArray(), "PKCS12")
                .withTrustStore("truststore.p12", "secret".toCharArray(), "PKCS12")
                .build();

        SSLContext sslContext = sslFactory.getSslContext();
        HostnameVerifier hostnameVerifier = sslFactory.getHostnameVerifier();
        Optional<X509ExtendedKeyManager> keyManager = sslFactory.getKeyManager();
        X509ExtendedTrustManager trustManager = sslFactory.getTrustManager();
        X509Certificate[] trustedCertificates = sslFactory.getTrustedCertificates();
        List<KeyStoreHolder> identities = sslFactory.getIdentities();
        List<KeyStoreHolder> trustStores = sslFactory.getTrustStores();
    }

}
```
#### Other possible configurations
One way authentication with custom trustStore 
```text
SSLFactory.builder()
          .withTrustStore(trustStore, trustStorePassword)
          .build();
```

One way authentication while trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withTrustingAllCertificatesWithoutValidation()
          .build();
```

One way authentication with specific encryption protocol version, custom secure random and option to validate the hostname within the request against the SAN field of a certificate.
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol. Just provide `TLSv1.3` as protocol argument and it will work out-of-the-box.
```text
SSLFactory.builder()
          .withTrustStore(trustStore, trustStorePassword)
          .withHostnameVerifier(hostnameVerifier)
          .withSecureRandom(secureRandom)
          .withProtocol("TLSv1.2")
          .build();
```

Two way authentication with custom trustStore, hostname verifier and encryption protocol version
```text
SSLFactory.builder()
          .withIdentity(identity, identityPassword)
          .withTrustStore(trustStore, trustStorePassword)
          .withHostnameVerifier(hostnameVerifier)
          .withProtocol("TLSv1.2")
          .build();
```

Support for using multiple identities and trustStores 
```text
SSLFactory.builder()
          .withIdentity(identityA, identityPasswordA)
          .withIdentity(identityB, identityPasswordB)
          .withIdentity(identityC, identityPasswordC)
          .withTrustStore(trustStoreA, trustStorePasswordA)
          .withTrustStore(trustStoreB, trustStorePasswordB)
          .withTrustStore(trustStoreC, trustStorePasswordC)
          .withTrustStore(trustStoreD, trustStorePasswordD)
          .withProtocol("TLSv1.2")
          .build();
```

Support for using X509KeyManager and X509TrustManager
```text
SSLFactory.builder()
          .withKeyManager(keyManager)
          .withTrustManager(trustManager)
          .build();
```

### Additional mappers for specific libraries
Some http clients relay on different ssl classes from third parties and require mapping from SSLFactory to those libraries.
Below you will find the maven dependency which will provide the mapping and also the SSLFactory library.
When using one of the below libraries, it is not required to also explicitly include [sslcontext-kickstart](#install-with-mavenhttpsmvnrepositorycomartifactiogithubhakky54sslcontext-kickstart).
#### Netty
Some know http clients which relay on netty libraries are: [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html), [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) and [Dispatch Reboot Http Client](https://github.com/dispatch/reboot).
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-netty</artifactId>
    <version>3.0.9</version>
</dependency>
```
Example setup for Spring WebClient with Netty:
```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.NettySslContextUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create()
                .secure(sslSpec -> sslSpec.sslContext(sslContext));

        WebClient webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Jetty
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-jetty</artifactId>
    <version>3.0.9</version>
</dependency>
```
Example setup for [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html):
```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.JettySslContextUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();
        
        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);
        HttpClient httpClient = new HttpClient(sslContextFactory);

        WebClient webClient = WebClient.builder()
                .clientConnector(new JettyClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Apache
Apache Http Client works with javax.net.ssl.SSLContext, so an additional mapping to their library is not required, [see here](#example-configuration).
However it is still possible to configure the http client with their custom configuration class. you can find below an example configuration for that use case:
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-apache</artifactId>
    <version>3.0.9</version>
</dependency>
```
```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.ApacheSslContextUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        LayeredConnectionSocketFactory socketFactory = ApacheSslContextUtils.toLayeredConnectionSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
    }

}
```

## Tested HTTP Clients
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

**Kotlin**
* [Fuel](https://github.com/kittinunf/fuel) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FuelService.kt)
* [Kohttp](https://github.com/rybalkinsd/kohttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KohttpService.kt)

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