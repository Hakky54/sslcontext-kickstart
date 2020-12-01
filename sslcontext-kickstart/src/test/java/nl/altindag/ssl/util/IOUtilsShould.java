package nl.altindag.ssl.util;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class IOUtilsShould {

    @Test
    void getContent() throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream("Hello".getBytes());
        String content = IOUtils.getContent(inputStream);
        assertThat(content).isEqualTo("Hello");
    }

}
