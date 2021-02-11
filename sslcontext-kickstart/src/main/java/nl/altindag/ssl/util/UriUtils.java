package nl.altindag.ssl.util;

import java.net.URI;

import static java.util.Objects.isNull;

public final class UriUtils {

    private UriUtils() {}

    public static void validate(URI uri) {
        if (isNull(uri)) {
            throw new IllegalArgumentException("host should be present");
        }

        if (isNull(uri.getHost())) {
            throw new IllegalArgumentException("hostname should be defined");
        }

        if (uri.getPort() == -1) {
            throw new IllegalArgumentException("port should be defined");
        }
    }

}
