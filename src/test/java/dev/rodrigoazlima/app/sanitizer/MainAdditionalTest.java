package dev.rodrigoazlima.app.sanitizer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class MainAdditionalTest {

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
        return outContent.toString(StandardCharsets.UTF_8).replace("\r\n", "\n");
    }

    @Test
    @DisplayName("Concatenation skips pieces that sanitize to empty")
    void concatenationSkipsEmptyPieces() {
        String[] args = {";rm -rf /", "ok"};
        Main.main(args);
        assertEquals("ok\n", normalizedOut());
    }

    @Test
    @DisplayName("All pieces empty results in empty line output")
    void allPiecesEmptyResultsInEmptyLine() {
        String[] args = {"<script></script>", "%;'\n\r"};
        Main.main(args);
        assertEquals("\n", normalizedOut());
    }
}
