package nl.altindag.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static nl.altindag.ssl.TestConstants.HOME_DIRECTORY;

/**
 * @author Hakan Altindag
 */
public final class IOTestUtils {

    private IOTestUtils() {}

    public static Path copyFileToHomeDirectory(String path, String fileName) throws IOException {
        try (InputStream inputStream = getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(HOME_DIRECTORY, fileName);
            Files.copy(Objects.requireNonNull(inputStream), destination, REPLACE_EXISTING);
            return destination;
        }
    }

    public static InputStream getResourceAsStream(String path) {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
    }

}
