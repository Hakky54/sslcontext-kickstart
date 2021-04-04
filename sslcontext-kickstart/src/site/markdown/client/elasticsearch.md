## ElasticSearch - Example SSL RestHighLevelClient Configuration

```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.CertificateUtils;
import org.apache.http.HttpHost;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.List;

public class App {

    public static void main(String[] args) throws IOException {
        List<Certificate> certificates = CertificateUtils.loadCertificate(Paths.get("ca.crt").toAbsolutePath());
        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(certificates)
                .build();

        RestClientBuilder restClientBuilder = RestClient.builder(new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(httpClientBuilder ->
                        httpClientBuilder.setSSLContext(sslFactory.getSslContext()));

        try(RestHighLevelClient client = new RestHighLevelClient(restClientBuilder)) {
            ClusterHealthResponse healthResponse = client.cluster().health(new ClusterHealthRequest(), RequestOptions.DEFAULT);
            System.out.println(healthResponse);
        }
    }

}
```

###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.