package nl.altindag.sslcontext.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.stream.Collectors;

public final class IOUtils {

    private static final String NEW_LINE = "\n";

    private IOUtils() {}

    public static String getContent(InputStream inputStream) throws IOException {
        try (InputStreamReader inputStreamReader = new InputStreamReader(Objects.requireNonNull(inputStream), StandardCharsets.UTF_8);
             BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            return bufferedReader.lines()
                    .collect(Collectors.joining(NEW_LINE));
        }
    }

}
