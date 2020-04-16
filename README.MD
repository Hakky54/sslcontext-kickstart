[![Actions Status](https://github.com/Hakky54/sslcontext-kickstart/workflows/Build/badge.svg)](https://github.com/Hakky54/sslcontext-kickstart/actions)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=security_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=coverage)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/sslcontext-kickstart/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/sslcontext-kickstart/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)

# Install with [maven](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart</artifactId>
    <version>3.0.8</version>
</dependency>
```

## Table of contents
1. [Introduction](#introduction)
2. [Acknowledgement](#acknowledgement)
3. [Advantages](#advantages)
4. [Definitions](#definitions)
5. [Tested HTTP Clients](#tested-http-clients)
6. [Usage](#usage)
   - [Example configuration](#example-configuration)
   - [Other possible configurations](#other-possible-configurations)
7. [Additional mappers for specific libraries](#additional-mappers-for-specific-libraries)
   - [Netty](#netty)
   - [Jetty](#jetty)
   - [Apache](#apache)

## Introduction
SSLContext Kickstart is a library which provides an easy to use [Factory class](#usage) for configuring a http client to communicate over SSL/TLS for one way authentication or two way authentication.

## Acknowledgement
I would like to thank [Cody A. Ray](https://github.com/codyaray) for his contribution to the community regarding loading multiple Keystores into the SSLContext. The limitation of the JDK is to only support one keystore for the KeyManagerFactory and only one keystore for the TrustManagerFactory.
The code snippets which Cody has shared are now available within this library and can be found here: [CompositeX509KeyManager](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/keymanager/CompositeX509ExtendedKeyManager.java) and [CompositeX509TrustManager](sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/trustmanager/CompositeX509ExtendedTrustManager.java) 

The original article can be found here: [Codyaray - Java SSL with Multiple KeyStores](http://codyaray.com/2013/04/java-ssl-with-multiple-keystores).

## Advantages:
  - No need for low-level SSLContext configuration anymore
  - No knowledge needed about SSLContext, TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
  - Above classes will all be created with just providing an identity and a trustStore

## Definitions
  - Identity: A KeyStore which holds the key pair also known as private and public key
  - TrustStore: A KeyStore containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
  - One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
  - Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

## Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration
  - [Apache HttpClient](https://github.com/apache/httpcomponents-client)
  - [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html)
  - [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html)
  - [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html)
  - [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html)
  - [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html)
  - [OkHttp](https://github.com/square/okhttp)
  - [Jersey Client](https://eclipse-ee4j.github.io/jersey/)
  - Old Jersey Client
  - [Google HttpClient](https://github.com/googleapis/google-http-java-client)
  - [Unirest](https://github.com/Kong/unirest-java)
  - [Retrofit](https://github.com/square/retrofit)
  - [Twitter Finagle Http Client](https://github.com/twitter/finagle)
  - [Akka Http Client](https://github.com/akka/akka-http)
  - [Dispatch Reboot Http Client](https://github.com/dispatch/reboot)
  - [Async Http Client](https://github.com/AsyncHttpClient/async-http-client)
  - [ScalaJ Http Client](https://github.com/scalaj/scalaj-http)  
  
There is a github project available named [Mutual-tls-ssl](https://github.com/Hakky54/mutual-tls-ssl) which provides a tutorial containing steps for setting up these four scenarios:
  - No security
  - One way authentication
  - Two way authentication
  - Two way authentication with trusting the Certificate Authority

It will also explain how to create KeyStores, Certificates, Certificate Signing Requests and how to implement it.

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
    <version>3.0.8</version>
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
    <version>3.0.8</version>
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
    <version>3.0.8</version>
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