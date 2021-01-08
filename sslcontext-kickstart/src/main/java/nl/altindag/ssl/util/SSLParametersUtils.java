package nl.altindag.ssl.util;

import javax.net.ssl.SSLParameters;
import java.util.Optional;

public final class SSLParametersUtils {

    private SSLParametersUtils() {}

    public static SSLParameters copy(SSLParameters source) {
        SSLParameters target = new SSLParameters();
        target.setProtocols(source.getProtocols());
        target.setCipherSuites(source.getCipherSuites());
        return target;
    }

    public static SSLParameters merge(SSLParameters baseSslParameters, SSLParameters alternativeSslParameters) {
        SSLParameters target = new SSLParameters();

        String[] ciphers = Optional.ofNullable(baseSslParameters.getCipherSuites())
                .orElse(alternativeSslParameters.getCipherSuites());
        String[] protocols = Optional.ofNullable(baseSslParameters.getProtocols())
                .orElse(alternativeSslParameters.getProtocols());

        target.setCipherSuites(ciphers);
        target.setProtocols(protocols);
        return target;
    }

}
