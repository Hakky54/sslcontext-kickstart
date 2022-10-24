[![Actions Status](https://github.com/Hakky54/sslcontext-kickstart/workflows/Build/badge.svg)](https://github.com/Hakky54/sslcontext-kickstart/actions)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=security_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Known Vulnerabilities](https://snyk.io/test/github/Hakky54/sslcontext-kickstart/badge.svg)](https://snyk.io/test/github/Hakky54/sslcontext-kickstart)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart-parent&metric=coverage)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)
[![Language grade: Java](https://img.shields.io/lgtm/grade/java/g/Hakky54/sslcontext-kickstart.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Hakky54/sslcontext-kickstart/context:java)
[![JDK compatibility: 8+](https://img.shields.io/badge/JDK_compatibility-8+-blue.svg)](#)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/sslcontext-kickstart/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/sslcontext-kickstart/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
[![javadoc](https://javadoc.io/badge2/io.github.hakky54/sslcontext-kickstart/javadoc.svg)](https://javadoc.io/doc/io.github.hakky54/sslcontext-kickstart)
[![Dependencies: none](https://img.shields.io/badge/dependencies-1-blue.svg)](#)
[![GitHub stars chart](https://img.shields.io/badge/github%20stars-chart-blue.svg)](https://seladb.github.io/StarTrack-js/#/preload?r=hakky54,sslcontext-kickstart)
[![Join the chat at https://gitter.im/hakky54/sslcontext-kickstart](https://badges.gitter.im/hakky54/sslcontext-kickstart.svg)](https://gitter.im/hakky54/sslcontext-kickstart?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart-parent)

# SSLContext Kickstart 🔐 [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Easily%20configure%20ssl/tls%20for%20your%20favourite%20http%20client%20with%20sslcontext-kickstart.%20Works%20with%20over%2040%20different%20java,%20scala,%20kotlin%20clients&url=https://github.com/Hakky54/sslcontext-kickstart&via=hakky541&hashtags=encryption,security,https,ssl,tls,developer,java,scala,kotlin,sslcontextkickstart)

# Install library with:
### Install with [Maven](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart</artifactId>
    <version>7.4.8</version>
</dependency>
```
### Install with Gradle
```groovy
implementation 'io.github.hakky54:sslcontext-kickstart:7.4.8'
```
### Install with Gradle Kotlin DSL
```kotlin
implementation("io.github.hakky54:sslcontext-kickstart:7.4.8")
```
### Install with Scala SBT
```
libraryDependencies += "io.github.hakky54" % "sslcontext-kickstart" % "7.4.8"
```
### Install with Apache Ivy
```xml
<dependency org="io.github.hakky54" name="sslcontext-kickstart" rev="7.4.8" />
```

## Table of contents
1. [Introduction](#introduction)
   - [History](#history)
   - [Acknowledgement](#acknowledgement)
   - [Advantages](#advantages)
   - [Definitions](#definitions)
2. [Usage](#usage)
   - [Example configuration](#basic-example-configuration)
   - [Other possible configurations](#other-possible-configurations)
     - [Loading keystore from the classpath](#loading-keystore-and-truststore-from-the-classpath)
     - [Loading keystore from the file system](#loading-keystore-and-trust-store-from-anywhere-on-the-filesystem)
     - [Loading keystore from InputStream](#loading-keystore-and-trust-store-from-inputstream)
     - [Loading trust material with OCSP options](#loading-trust-material-with-ocsp-options)
         - [TrustStore from the classpath](#loading-trust-material-with-truststore-and-ocsp-options-from-the-classpath)
         - [TrustStore from the file system](#loading-trust-material-with-truststore-and-ocsp-options-from-the-file-system)
         - [TrustManager](#loading-trust-material-with-trustmanager-and-ocsp-options)
         - [Certificates](#loading-trust-material-with-certificates-and-ocsp-options)
     - [Enhanceable trust validations](#enhanceable-trust-validations)
     - [Skip certificate validation](#trusting-all-certificates-without-validation-not-recommended-to-use-at-production)
     - [Skip hostname validation](#skip-hostname-validation)
     - [Loading JDK and OS trusted certificates](#loading-jdk-and-os-trusted-certificates)
     - [Using specific protocols and ciphers with custom secure-random and hostname-verifier](#using-specific-protocols-ciphers-with-custom-secure-random-and-hostname-verifier)
     - [Using multiple identity materials and trust materials](#support-for-using-multiple-identity-materials-and-trust-materials)
     - [Using custom KeyManager and TrustManager](#support-for-using-x509extendedkeymanager-and-x509extendedtrustmanager)
     - [Using dummy identity and trust material](#using-dummy-identity-and-trust-material)
     - [Using KeyStore with multiple keys having different passwords](#support-for-using-a-single-keystore-which-contains-multiple-keys-with-different-passwords)
     - [Using custom PrivateKey and Certificates](#support-for-using-privatekey-and-certificates)
     - [Reloading SSL at runtime](#support-for-reloading-ssl-at-runtime)
     - [Hot swap KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime)
     - [Routing client identity to specific host](#routing-identity-material-to-specific-host) 
     - [Updating client identity routes at runtime](#updating-identity-routes-at-runtime) 
     - [Managing ssl session](#managing-ssl-session)
     - [Extracting server certificates](#extracting-server-certificates)  
     - [Using P7B or PKCS#7 files](#using-p7b-or-pkcs7-files)
     - [Using DER files](#using-der-files)
     - [Using PFX or P12 or PKCS#12 Files](#using-pfx-p12-or-pkcs12-files)
     - [Using PEM Files](#using-pem-files)
       - [Loading pem files from the classpath](#loading-pem-files-from-the-classpath)
       - [Loading pem files from the file system](#loading-pem-files-from-anywhere-on-the-filesystem)
       - [Loading pem files from InputStream](#loading-pem-files-from-inputstream)
       - [Loading pem files from string content](#loading-pem-files-from-string-content)
       - [Loading encrypted pem files](#loading-encrypted-pem-files)
     - [Migrating from classic configuration](#migrating-from-classic-configuration)
   - [Returnable values from the SSLFactory](#returnable-values-from-the-sslfactory)
3. [Additional mappers for specific libraries](#additional-mappers-for-specific-libraries)
   - [Netty](#netty)
   - [Jetty](#jetty)
   - [Apache](#apache)
     - [Apache 4](#apache-4)
     - [Apache 5](#apache-5)
4. [Tested HTTP Clients](#tested-http-clients)
5. [Contributing](#contributing)
6. [Contributors](#contributors-)   
7. [License](#license)

## Introduction
Hey, hello there 👋 Welcome, you are ![visitors](https://visitor-badge.glitch.me/badge?page_id=https://github.com/Hakky54/sslcontext-kickstart) I hope you will like this library ❤️

SSLContext Kickstart is a library which provides a High-Level SSLFactory class for configuring a http client or a server to communicate over SSL/TLS for one way authentication or two-way authentication.
It is designed to be as lightweight as possible by having minimized the external dependencies. The core library only depends on the SLF4J logging API.

### History
As a Java developer I worked for different kinds of clients. Most of the time the application required to call other microservices within the organization or some other http servers. 
These requests needed to be secured, and therefore it was required to load the ssl materials into the http client. Each http client may require different input value to enable https requests, and therefore I couldn't just copy-paste my earlier configuration into the new project. 
The resulting configuration was in my opinion always verbose, not reusable, hard to test and hard to maintain. 

As a developer you also need to know how to properly load your file into your application and consume it as a KeyStore instance. Therefore, you also need to understand how to properly create for example a KeyManager and a TrustManager for you SSLContext. 
The sslcontext-kickstart library is taking the responsibility of creating an instance of SSLContext from the provided arguments, and it will provide you all the ssl materials which are required to configure [40+ different Http Client](#tested-http-clients) for Java, Scala and Kotlin. 
I wanted the library to be as easy as possible to use for all developers to give them a kickstart when configuring their Http Client. So feel free to provide feedback or feature requests.
The library also provides other utilities such as:
- [CertificateUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/CertificateUtils.java)
- [HostnameVerifierUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/HostnameVerifierUtils.java)
- [KeyStoreUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/KeyStoreUtils.java)
- [KeyManagerUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/KeyManagerUtils.java)
- [TrustManagerUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/TrustManagerUtils.java)
- [PemUtils](sslcontext-kickstart-for-pem/src/main/java/nl/altindag/ssl/util/PemUtils.java)
- [SSLContextUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLContextUtils.java)
- [SSLFactoryUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLFactoryUtils.java)
- [SSLSessionUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLSessionUtils.java)
- [SSLSocketUtils](sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLSocketUtils.java)

See the [javadoc](https://sslcontext-kickstart.com/apidocs/index.html) for all the options.

### Acknowledgement
I would like to thank [Cody A. Ray](https://github.com/codyaray) for his contribution to the community regarding loading multiple Keystores into the SSLContext. The limitation of the JDK is to only support one keystore for the KeyManagerFactory and only one keystore for the TrustManagerFactory.
The code snippets which Cody has shared are now available within this library and can be found here: [CompositeX509KeyManager](sslcontext-kickstart/src/main/java/nl/altindag/ssl/keymanager/CompositeX509ExtendedKeyManager.java) and [CompositeX509TrustManager](sslcontext-kickstart/src/main/java/nl/altindag/ssl/trustmanager/CompositeX509ExtendedTrustManager.java) 

The original content can be found here:
- [Codyaray - Java SSL with Multiple KeyStores](http://codyaray.com/2013/04/java-ssl-with-multiple-keystores)
- [Stackoverflow - Registering multiple keystores in JVM](https://stackoverflow.com/a/16229909/6777695)

### Advantages:
* No need for low-level SSLContext configuration anymore
* No knowledge needed about SSLContext, TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
* Above classes will all be created with just providing an identity and a trust material
* Load multiple identities/trustStores/keyManagers/trustManagers
* Hot reload ssl material without need of restarting/recreating Http Client or Server

### Definitions
* Identity material: A KeyStore or KeyManager which holds the key pair also known as private and public key
* Trust material: A KeyStore or TrustManager containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
* One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
* Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

## Usage
### Basic example configuration
Example configuration with apache http client, or [click here to view the other client configurations](#tested-http-clients)
```java
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import nl.altindag.ssl.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException, JSONException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
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
##### Loading keystore and truststore from the classpath
```text
SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .build();
```

##### Loading keystore and trust store from anywhere on the filesystem
```text
SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
```

##### Loading keystore and trust store from InputStream
```text
InputStream keyStoreStream = ...
InputStream trustStoreStream = ...

SSLFactory.builder()
          .withIdentityMaterial(keyStoreStream, "password".toCharArray())
          .withTrustMaterial(trustStoreStream, "password".toCharArray())
          .build();
```

##### Loading trust material with OCSP options
##### Loading trust material with TrustStore and OCSP options from the classpath
```text
CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial("truststore.jks", "password".toCharArray(), trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```
##### Loading trust material with TrustStore and OCSP options from the file system
```text
CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray(), trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```
##### Loading trust material with TrustManager and OCSP options
```text
X509ExtendedTrustManager trustManager = ...

CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(trustManager, trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```

##### Loading trust material with certificates and OCSP options
```text
List<Certificate> certificates = ...

CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(certificates, trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```

##### Enhanceable trust validations
By default, the TrustManager ships with default validations to validate if the counterparty is trusted during the SSL Handshake. 
If needed the default behaviour can be overruled by custom validators.
If a custom validator is specified and if the condition evaluates to true, then the certificate of the counterparty will be trusted. If the condition evaluates to false, than it will fall back to the default behaviour of the TrustManager.
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withTrustEnhancer((X509Certificate[] certificateChain, String authType) ->
                  certificateChain[0].getIssuerX500Principal().getName().equals("Foo")
                      && certificateChain[0].getSubjectX500Principal().getName().equals("Bar"))
          .build();
```

Chaining of multiple validators is possible with the following snippet:
```text
ChainAndAuthTypeValidator validator = ((ChainAndAuthTypeValidator) 
        (certificateChain, authType) -> certificateChain[0].getIssuerX500Principal().getName().equals("Foo"))
        .and((certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().equals("Bar"))
        .and((certificateChain, authType) -> certificateChain[0].getIssuerX500Principal().getName().equals("MyCompany"))
        .or((certificateChain, authType) -> certificateChain[0].getIssuerX500Principal().getName().equals("TheirCompany"));

SSLFactory sslFactory = SSLFactory.builder()
        .withDefaultTrustMaterial()
        .withTrustEnhancer(validator)
        .build();
```

The method has overloaded methods, and it is recommended to apply similar validators to the overloaded methods. The signature of the methods are:
```text
SSLFactory sslFactory = SSLFactory.builder()
        .withDefaultTrustMaterial()
        .withTrustEnhancer(((X509Certificate[] certificateChain, String authType) -> myConditionWhichReturnsBoolean))
        .withTrustEnhancer(((X509Certificate[] certificateChain, String authType, Socket socket) -> myConditionWhichReturnsBoolean))
        .withTrustEnhancer(((X509Certificate[] certificateChain, String authType, SSLEngine sslEngine) -> myConditionWhichReturnsBoolean))
        .build();
```

##### Trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withUnsafeTrustMaterial()
          .build();
```

##### Skip hostname validation
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withUnsafeHostnameVerifier()
          .build();
```

##### Loading JDK and OS trusted certificates
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withSystemTrustMaterial()
          .build();
```

##### Using specific protocols, ciphers with custom secure random and hostname verifier
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol by default.
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withProtocols("TLSv1.3", "TLSv1.2")
          .withCiphers("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
          .withHostnameVerifier(hostnameVerifier)
          .withSecureRandom(secureRandom)
          .build();
```

##### Support for using multiple identity materials and trust materials
```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withIdentityMaterial("identity-3.jks", password)
          .withIdentityMaterial("identity-4.jks", password)
          .withTrustMaterial("truststore-1.jks", password)
          .withTrustMaterial("truststore-2.jks", password)
          .withTrustMaterial("truststore-3.jks", password)
          .withTrustMaterial("truststore-4.jks", password)
          .build();
```
In some use cases multiple identities can fail to work. If that happens please try to add the additional SSLFactory option of identity route. See here for more: [Routing identity to specific host](#routing-identity-material-to-specific-host)

##### Support for using X509ExtendedKeyManager and X509ExtendedTrustManager
```text
X509ExtendedKeyManager keyManager = ...
X509ExtendedTrustManager trustManager = ...

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```

##### Using dummy identity and trust material
In some use cases it may be useful to use a dummy identity or trust material. An example use case would be to create a base SSLFactory with the dummies which can be swapped afterwords. See below for a refactored version of [Support for swapping KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime).
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withDummyIdentityMaterial()
          .withDummyTrustMaterial()
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()
          
Runnable sslUpdater = () -> {
    SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
    
    SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);
};

// initial update of ssl material to replace the dummies
sslUpdater.run();
   
// update ssl material every hour    
Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(sslUpdater, 1, 1, TimeUnit.HOURS);

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
##### Support for using a single KeyStore which contains multiple keys with different passwords
```text
KeyStore keyStore = ...
X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStore, Map.of(
        "foo","foo-password".toCharArray(),
        "bar","bar-password".toCharArray(),
        "lorum-ipsum","lorum-ipsum-password".toCharArray()
));

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withDefaultTrustMaterial()
          .build();
```
##### Support for using PrivateKey and Certificates
```text
PrivateKey privateKey = ...
char[] privateKeyPassword = ...
Certificate[] certificateChain = ...

Certificate trustedCertificate = ...

SSLFactory.builder()
          .withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
          .withTrustMaterial(trustedCertificate)
          .build();
```
##### Support for reloading ssl at runtime
It is possible to reload or update the ssl configuration while already using it with your client or server without the need of restarting your application or recreating it with SSLFactory. The identity and trust material may expire at some point in time and needs to be replaced to be still functional.
Restart of the application with a traditional setup is unavoidable and can result into a downtime for x amount of time. A restart is not needed when using the setup below. The below example is a high-level method of reloading the ssl configuration, if you prefer to use a low-level setup please have a look at the following example displayed here: [Hot swap KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime).
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withDummyIdentityMaterial()
          .withDummyTrustMaterial()
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()
          
Runnable sslUpdater = () -> {
    SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
    
    SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);
};

// initial update of ssl material to replace the dummies
sslUpdater.run();
   
// update ssl material every hour    
Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(sslUpdater, 1, 1, TimeUnit.HOURS);

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
See here for a basic reference implementation for a server: [GitHub - Instant SSL Reloading](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading)
##### Support for swapping KeyManager and TrustManager at runtime
It is possible to swap a KeyManager and TrustManager from a SSLContext, SSLSocketFactory and SSLServerSocketFactory while already using it within your client or server at runtime. This option will enable to refresh the identity and trust material of a server or client without the need of restarting your application or recreating it with SSLFactory. The identity and trust material may expire at some point in time and needs to be replaced to be still functional.
Restart of the application with a traditional setup is unavoidable and can result into a downtime for x amount of time. A restart is not needed when using the setup below.
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()

// execute https request
HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());

SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
          
// swap identity and trust materials and reuse existing http client
KeyManagerUtils.swapKeyManager(baseSslFactory.getKeyManager().get(), updatedSslFactory.getKeyManager().get());
TrustManagerUtils.swapTrustManager(baseSslFactory.getTrustManager().get(), updatedSslFactory.getTrustManager().get());

// Cleanup old ssl sessions by invalidating them all. Forces to use new ssl sessions which will be created by the swapped KeyManager/TrustManager
SSLSessionUtils.invalidateCaches(baseSslFactory.getSslContext());

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
See here for a basic reference implementation for a server: [GitHub - Instant SSL Reloading](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading)
##### Routing identity material to specific host
It may occur that the client is sending the wrong certificate to the server when using multiple identities. This will happen when the client certificate has insufficient information for the underlying ssl engine (the KeyManager) and therefore it cannot select the right certificate.
Recreating the certificates can resolve this issue. However, if that is not possible you can provide an option to the engine to use a specific certificate for a given server. Below is an example setup for correctly routing the client identity based on the alias which can be found within the KeyStore file.
```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();
```
##### Updating identity routes at runtime
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();

X509ExtendedKeyManager keyManager = sslFactory.getKeyManager().get()

// Add additional routes next to the existing ones
KeyManagerUtils.addIdentityRoute(keyManager, "client-alias-one", "https://localhost:8463/", "https://localhost:8473/")

// Override existing routes
KeyManagerUtils.overrideIdentityRoute(keyManager, "client-alias-two", "https://localhost:9463/", "https://localhost:9473/")
```
##### Managing ssl session
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .withSessionTimeout(3600) // Amount of seconds until it will be invalidated
          .withSessionCacheSize(1024) // Amount of bytes until it will be invalidated
          .build();
          
SSLContext sslContext = sslFactory.getSslContext();
          
// Caches can be invalidated with the snippet below
SSLSessionUtils.invalidateCaches(sslContext);

// or any other option:
SSLSessionUtils.invalidateCachesBefore(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, JANUARY, 1, 15, 55), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesAfter(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, FEBRUARY, 10, 8, 14), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesBetween(
        sslContext,
        ZonedDateTime.now().minusHours(2),    // from
        ZonedDateTime.now()                   // up till
);
```
##### Extracting server certificates
```text
Map<String, List<Certificate>> certificates = CertificateUtils.getCertificate(
            "https://github.com/", 
            "https://stackoverflow.com/", 
            "https://www.reddit.com/",
            "https://www.youtube.com/");
            
// or get the server certificates as pem format
Map<String, List<String>> certificatesAsPem = CertificateUtils.getCertificateAsPem(
            "https://github.com/", 
            "https://stackoverflow.com/", 
            "https://www.reddit.com/",
            "https://www.youtube.com/");
```
See here for a demo application: [GitHub - Certificate Ripper](https://github.com/Hakky54/certificate-ripper)

#### Using P7B or PKCS#7 Files
Support for using p7b formatted certificates and certificate-chain from classpath, any directory or as an InputStream. 
P7b file is a text file containing a `-----BEGIN PKCS7-----` as header, `-----END PKCS7-----` as footer and has a Base64 encoded data between it.
```
List<Certificate> certificates = CertificateUtils.loadCertificate("certificate.p7b");

SSLFactory.builder()
          .withTrustMaterial(certificates)
          .build();
```

#### Using DER Files
Support for using der formatted certificates and certificate-chain from classpath, any directory or as an InputStream.
Der file is a binary form of a certificate. Commonly used extensions are `.cer` and `crt`.
```
List<Certificate> certificates = CertificateUtils.loadCertificate("certificate.cer");

SSLFactory.builder()
          .withTrustMaterial(certificates)
          .build();
```

#### Using PFX, P12 or PKCS#12 Files
PFX and p12 are both PKCS#12 type keystores which are supported.

```text
SSLFactory.builder()
          .withIdentityMaterial("identity.p12", "password".toCharArray())
          .withTrustMaterial("truststore.p12", "password".toCharArray())
          .build();
```

#### Using PEM Files
Support for using pem formatted private key and certificates from classpath, any directory or as an InputStream. See [PemUtilsShould](sslcontext-kickstart-for-pem/src/test/java/nl/altindag/ssl/util/PemUtilsShould.java) for detailed usages.
Add the dependency below to use this feature, it also includes the core features from the library such as SSLFactory.
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-pem</artifactId>
    <version>7.4.8</version>
</dependency>
```
##### Loading pem files from the classpath
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem");
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("some-trusted-certificate.pem");

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```
##### Loading pem files from anywhere on the filesystem
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(Paths.get("/path/to/your/certificate.pem"), Paths.get("/path/to/your/"private-key.pem"));
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(Paths.get("/path/to/your/"some-trusted-certificate.pem"));
```
##### Loading pem files from InputStream
```
InputStream privateKey = ...
InputStream certificate = ...
InputStream trustedCertificates = ...

X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificate, privateKey);
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(trustedCertificates);
```
##### Loading pem files from string content
```
String privateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
        "-----END ENCRYPTED PRIVATE KEY-----\n";

String certificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=\n" +
        "-----END CERTIFICATE-----\n";

String trustedCertificates =
        "-----BEGIN CERTIFICATE-----\n" +
        "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
        "-----END CERTIFICATE-----\n";

X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(certificate, privateKey, "secret".toCharArray());
X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(trustedCertificates);
```
##### Loading encrypted pem files
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem", "secret".toCharArray());
```
##### Migrating from classic configuration
Below is an example of the classic configuration for enabling ssl for your application.
```
-Djavax.net.ssl.trustStore=/path/to/truststore.jks
-Djavax.net.ssl.trustStoreType=jks
-Djavax.net.ssl.trustStorePassword=changeit
-Djavax.net.ssl.trustStoreProvider=SunJSSE

-Djavax.net.ssl.keyStore=/path/to/keystore.jks
-Djavax.net.ssl.keyStoreType=jks
-Djavax.net.ssl.keyStorePassword=changeit
-Djavax.net.ssl.keyStoreProvider=SunJSSE

-Dhttps.protocols=TLSv1.3
-Dhttps.cipherSuites=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

SSLFactory can be used with these properties together with the existing properties with the following snippet:
```
SSLFactory sslFactory = SSLFactory.builder()
        .withSystemPropertyDerivedIdentityMaterial()
        .withSystemPropertyDerivedTrustMaterial()
        .withSystemPropertyDerivedProtocols()
        .withSystemPropertyDerivedCiphers()
        .build();

SSLContext.setDefault(sslFactory.getSslContext());
```

The SSLFactory returnable values can be supplied to the http client as shown [here](#tested-http-clients)

### Returnable values from the SSLFactory
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
        Optional<KeyManagerFactory> keyManagerFactory = sslFactory.getKeyManagerFactory();
        Optional<TrustManagerFactory> trustManagerFactory = sslFactory.getTrustManagerFactory();
        List<X509Certificate> trustedCertificates = sslFactory.getTrustedCertificates();
        SSLSocketFactory sslSocketFactory = sslFactory.getSslSocketFactory();
        SSLServerSocketFactory sslServerSocketFactory = sslFactory.getSslServerSocketFactory();
        SSLEngine sslEngine = sslFactory.getSslEngine(host, port);
        SSLParameters sslParameters = sslFactory.getSslParameters();
        List<String> ciphers = sslFactory.getCiphers();
        List<String> protocols = sslFactory.getProtocols();
    }

}
```

### Additional mappers for specific libraries
Some http clients relay on different ssl classes from third parties and require mapping from SSLFactory to those libraries.
Below you will find the maven dependency which will provide the mapping and also the SSLFactory library.
When using one of the below libraries, it is not required to also explicitly include [sslcontext-kickstart](#install-with-mavenhttpsmvnrepositorycomartifactiogithubhakky54sslcontext-kickstart) into your project. The additional mappers for specific libraries below won't provide transitive dependencies on Netty, Jetty or Apache. This has been decided to prevent dependency hell on your side.
#### Netty
Some know http clients which relay on netty libraries are: [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html), [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) and [Dispatch Reboot Http Client](https://github.com/dispatch/reboot).
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-netty</artifactId>
    <version>7.4.8</version>
</dependency>
```
Example setup for Spring WebClient with Netty:
```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.NettySslUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        SslContext sslContext = NettySslUtils.forClient(sslFactory).build();
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
    <version>7.4.8</version>
</dependency>
```
Example setup for [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html):
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.JettySslUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();
        
        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        HttpClient httpClient = new HttpClient(sslContextFactory);

        WebClient webClient = WebClient.builder()
                .clientConnector(new JettyClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Apache
##### Apache 4
Apache Http Client works with javax.net.ssl.SSLContext, so an additional mapping to their library is not required, [see here](#example-configuration).
However it is still possible to configure the http client with their custom configuration class. you can find below an example configuration for that use case:
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-apache4</artifactId>
    <version>7.4.8</version>
</dependency>
```
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.Apache4SslUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache4SslUtils.toSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
    }

}
```
##### Apache 5
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-apache5</artifactId>
    <version>7.4.8</version>
</dependency>
```
```java
import nl.altindag.ssl.SSLFactory;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import nl.altindag.ssl.util.Apache5SslUtils;

class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache5SslUtils.toSocketFactory(sslFactory);
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();

        PoolingAsyncClientConnectionManager asyncConnectionManager = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(Apache5SslUtils.toTlsStrategy(sslFactory))
                .build();

        CloseableHttpAsyncClient httpAsyncClient = HttpAsyncClients.custom()
                .setConnectionManager(asyncConnectionManager)
                .build();
    }
    
}
```

## Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration

**Java**
* [Apache HttpClient](https://hc.apache.org/httpcomponents-client-4.5.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L68) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpClientService.java)
* [Apache HttpAsyncClient](https://hc.apache.org/httpcomponents-asyncclient-4.1.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L76) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpAsyncClientService.java)
* [Apache 5 HttpClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L86) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpClientService.java)
* [Apache 5 HttpAsyncClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples-async.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L97) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpAsyncClientService.java)
* [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L111) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JdkHttpClientService.java)
* [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJdkHttpClientService.java)
* [Netty Reactor](https://github.com/reactor/reactor-netty) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L134) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ReactorNettyService.java)
* [Jetty Reactive HttpClient](https://github.com/jetty-project/jetty-reactive-httpclient) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L142) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JettyReactiveHttpClientService.java)
* [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L119) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringRestTemplateService.java)
* [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L148) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L155) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [OkHttp](https://github.com/square/okhttp) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L125) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OkHttpClientService.java)
* [Jersey Client](https://eclipse-ee4j.github.io/jersey/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L162) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JerseyClientService.java)
* Old Jersey Client -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L170) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJerseyClientService.java)
* [Apache CXF JAX-RS](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L182) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFJaxRsClientService.java)
* [Apache CXF using ConduitConfigurer](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L191) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFWebClientService.java)
* [Google HttpClient](https://github.com/googleapis/google-http-java-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L206) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/GoogleHttpClientService.java)
* [Unirest](https://github.com/Kong/unirest-java) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L214) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/UnirestService.java)
* [Retrofit](https://github.com/square/retrofit) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L224) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RetrofitService.java)
* [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L262) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AsyncHttpClientService.java)
* [Feign](https://github.com/OpenFeign/feign) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L272) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FeignService.java)
* [Methanol](https://github.com/mizosoft/methanol) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L308) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/MethanolService.java)
* [Vertx Webclient](https://github.com/vert-x3/vertx-web) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L316) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/VertxWebClientService.java)
* [gRPC](https://grpc.io/) -> [Client/Server Configuration & Example request](https://github.com/Hakky54/java-tutorials)
* [ElasticSearch](https://www.elastic.co/) -> [RestHighLevelClient Configuration & example request](https://github.com/Hakky54/java-tutorials/blob/main/elasticsearch-with-ssl/src/main/java/nl/altindag/ssl/es/App.java)
* [Jetty WebSocket](https://www.eclipse.org/jetty/) -> [Client configuration & example request](https://github.com/Hakky54/java-tutorials/blob/2bf5d975347d500bb9d0aa3b32cbf33b345425ee/websocket-client-with-ssl/src/main/java/nl/altindag/ssl/ws/App.java#L14)

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
* [Ktor with Java engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorJavaHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Okhttp engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)

**Scala**
* [Twitter Finagle](https://github.com/twitter/finagle) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L233) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FinagleHttpClientService.java)
* [Twitter Finagle Featherbed](https://github.com/finagle/featherbed) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/d78e4e81b8b775d3ff09c11b0a7c1532a741199e/client/src/main/java/nl/altindag/client/service/FeatherbedRequestService.scala#L19)
* [Akka Http Client](https://github.com/akka/akka-http) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L253) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AkkaHttpClientService.java)
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

## Contributing

There are plenty of ways to contribute to this project:

* Give it a star
* Share it with a [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Easily%20configure%20ssl/tls%20for%20your%20favourite%20http%20client%20with%20sslcontext-kickstart.%20Works%20with%20over%2040%20different%20java,%20scala,%20kotlin%20clients&url=https://github.com/Hakky54/sslcontext-kickstart&via=hakky541&hashtags=encryption,security,https,ssl,tls,developer,java,scala,kotlin,sslcontextkickstart)
* Join the [Gitter room](https://gitter.im/hakky54/sslcontext-kickstart) and leave a feedback or help with answering users questions
* Submit a PR

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/MrR0807"><img src="https://avatars.githubusercontent.com/u/24605837?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Laurynas</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3AMrR0807" title="Code">💻</a> <a href="#maintenance-MrR0807" title="Maintenance">🚧</a></td>
    <td align="center"><a href="https://github.com/charphi"><img src="https://avatars.githubusercontent.com/u/8778378?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Philippe Charles</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Acharphi" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="http://tadhgpearson.wordpress.com"><img src="https://avatars.githubusercontent.com/u/1496586?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Tadhg Pearson</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Atadhgpearson" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/winster"><img src="https://avatars.githubusercontent.com/u/2383613?v=4?s=100" width="100px;" alt=""/><br /><sub><b>winster</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Awinster" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/lalloni"><img src="https://avatars.githubusercontent.com/u/84328?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Pablo Lalloni</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Alalloni" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/luismospinam"><img src="https://avatars.githubusercontent.com/u/25059970?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Luis Miguel Ospina</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Aluismospinam" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/Athou"><img src="https://avatars.githubusercontent.com/u/1256795?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Jérémie Panzer</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3AAthou" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/patpatpat123"><img src="https://avatars.githubusercontent.com/u/43899031?v=4?s=100" width="100px;" alt=""/><br /><sub><b>patpatpat123</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Apatpatpat123" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Apatpatpat123" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://codyaray.com"><img src="https://avatars.githubusercontent.com/u/44062?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Cody A. Ray</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/search?q=Cody%20Ray" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/chibenwa"><img src="https://avatars.githubusercontent.com/u/6928740?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Benoit Tellier</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Achibenwa" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/sal0max"><img src="https://avatars.githubusercontent.com/u/423373?v=4?s=100" width="100px;" alt=""/><br /><sub><b>sal0max</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Asal0max" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/lhstack"><img src="https://avatars.githubusercontent.com/u/42345796?v=4?s=100" width="100px;" alt=""/><br /><sub><b>lhstack</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Alhstack" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/dasteg"><img src="https://avatars.githubusercontent.com/u/3967403?v=4?s=100" width="100px;" alt=""/><br /><sub><b>dasteg</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Adasteg" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/rymsha"><img src="https://avatars.githubusercontent.com/u/2891483?v=4?s=100" width="100px;" alt=""/><br /><sub><b>rymsha</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Arymsha" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/manbucy"><img src="https://avatars.githubusercontent.com/u/24501621?v=4?s=100" width="100px;" alt=""/><br /><sub><b>manbucy</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Amanbucy" title="Code and Bug reports">🐛 💻</a></td>
    <td align="center"><a href="https://github.com/swankjesse"><img src="https://avatars.githubusercontent.com/u/133019?v=4?s=100" width="100px;" alt=""/><br /><sub><b>swankjesse</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Aswankjesse" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/ivenhov"><img src="https://avatars.githubusercontent.com/u/778457?v=4?s=100" width="100px;" alt=""/><br /><sub><b>ivenhov</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Aivenhov" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/ecki"><img src="https://avatars.githubusercontent.com/u/361432?v=4?s=100" width="100px;" alt=""/><br /><sub><b>ecki</b></sub></a><br /><a href="https://github.com/Hakky54/sslcontext-kickstart/issues?q=author%3Aecki" title="Code and Bug reports">🐛 💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart?ref=badge_large)
