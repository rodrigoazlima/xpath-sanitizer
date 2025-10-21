package dev.rodrigoazlima.app.sanitizer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    private final PrintStream originalOut = System.out;
    private ByteArrayOutputStream outContent;

    @BeforeEach
    void setUpStreams() {
        outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
    }

    private String normalizedOut() {
        // Normalize to just "\n" for stable assertions across OSes
        return outContent.toString(StandardCharsets.UTF_8).replace("\r\n", "\n");
    }

    @Test
    @DisplayName("Prints usage when args are null")
    void printsUsageWhenArgsNull() {
        Main.main(null);
        String expected = "Usage: java -jar xpath-sanitizer-1.0.0.jar <value1> [value2 ...]\n";
        assertEquals(expected, normalizedOut());
    }

    @Test
    @DisplayName("Prints usage when args are empty")
    void printsUsageWhenArgsEmpty() {
        Main.main(new String[]{});
        String expected = "Usage: java -jar xpath-sanitizer-1.0.0.jar <value1> [value2 ...]\n";
        assertEquals(expected, normalizedOut());
    }

    @Test
    @DisplayName("Sanitizes inputs, concatenates and prints result")
    void sanitizesConcatenatesAndPrints() {
        // Given: two inputs that will be sanitized and concatenated
        String[] args = {" report .txt ", "foo<script>alert(1)</script>bar"};
        // When
        Main.main(args);
        // Then: SanitizerImpl should sanitize to "report.txt" and "fooalert1bar" (tags stripped)
        String expected = "report.txtfooalert1bar\n";
        assertEquals(expected, normalizedOut());
    }
}
