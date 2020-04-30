### History
As a Java developer I worked for different kinds of clients. Most of the time the application required to call other microservices within the organization or some other http servers. 
It was required to be HTTPS configured and so I began writing the code which was needed to configure the Http Client to communicate over ssl/tls. And every time I needed to write almost the same code over and over again which is in my opinion very verbose and hard to unit test. See below for an example:
```java
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;

public class App {
    
    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, 
            KeyManagementException, IOException, CertificateException, UnrecoverableKeyException {
        
        String keyStorePath = "keystore.p12";
        String trustStorePath = "truststore.p12";
        
        char[] keyStorePassword = "secret".toCharArray();
        char[] trustStorePassword = "secret".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        
        
        try(InputStream keyStoreInputStream = App.class.getClassLoader().getResourceAsStream(keyStorePath);
            InputStream trustStoreInputStream = App.class.getClassLoader().getResourceAsStream(trustStorePath)) {

            Objects.requireNonNull(keyStoreInputStream);
            Objects.requireNonNull(trustStoreInputStream);
            
            keyStore.load(keyStoreInputStream, keyStorePassword);
            trustStore.load(trustStoreInputStream, trustStorePassword);
        }
        
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePassword);
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
    }
    
}
```
The above snippet is an example for creating a SSLContext with a key and a trust material. I am not only considering the amount of lines which needed to be written to create the SSLContext but it requires also a lot knowledge of the developer to just write this.
You need to know how to properly load your file into your application and consume it as a KeyStore instance. Therefor you also need to learn how to properly create a KeyManagerFactory, TrustManagerFactory and SSLContext. 
The above snippet needs to be rewritten if you use a Http Client which relies on libraries of Jetty or Netty and therefor it makes it even more complex. The code above can be rewritten with the snippet below:
```java
import nl.altindag.sslcontext.SSLFactory;

import javax.net.ssl.SSLContext;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentity("keystore.p12", "secret".toCharArray(), "PKCS12")
                .withTrustStore("truststore.p12", "secret".toCharArray(), "PKCS12")
                .build();
        
        SSLContext sslContext = sslFactory.getSslContext();
    }

}
```
The sslcontext-kickstart library is taking the responsibility of creating an instance of SSLContext from the provided arguments. I wanted to be as easy as possible to use to give every developer a kickstart when configuring their Http Client. So feel free to provide feedback or feature requests.
The library also provide other utilities such as [KeyStoreUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/KeyStoreUtils.java), [KeyManagerUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/KeyManagerUtils.java) and [TrustManagerUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/sslcontext/util/TrustManagerUtils.java). See the [javadoc](https://sslcontext-kickstart.com/apidocs/index.html) for all the options.

Other libraries also provide the same kind of factories/builders such as [Apache SSLContextBuilder](https://hc.apache.org/httpcomponents-core-4.4.x/httpcore/apidocs/org/apache/http/ssl/SSLContextBuilder.html) or [Netty SslContextBuilder](https://netty.io/4.0/api/io/netty/handler/ssl/SslContextBuilder.html) or [Jetty SslContextFactory](https://www.eclipse.org/jetty/javadoc/9.4.26.v20200117/org/eclipse/jetty/util/ssl/SslContextFactory.html) but the downside of using those libraries is that you also pull in their Http Client, transitive dependencies and other heavy not required classes.
It will therefor make your executable fat jar even more fatter. Therefor most of the developer prefer to write the code by themselves to instantiate an SSLContext instead of using the libraries of Apache, Netty and Jetty.