package dev.rodrigoazlima.app.sanitizer;

import dev.rodrigoazlima.app.sanitizer.impl.SanitizerImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SanitizerAdditionalTest {

    private final Sanitizer sanitizer = new SanitizerImpl();

    @Test
    @DisplayName("Truncates long input without extension to 255 chars")
    void truncatesLongInputWithoutExtension() {
        String input = "a".repeat(300);
        String result = sanitizer.sanitize(input);
        assertEquals(255, result.length());
        assertTrue(result.chars().allMatch(ch -> ch == 'a'));
    }

    @Test
    @DisplayName("Truncates long input with extension preserving extension")
    void truncatesLongInputWithExtension() {
        String input = "b".repeat(300) + ".log";
        String result = sanitizer.sanitize(input);
        assertTrue(result.length() <= 255);
        assertTrue(result.endsWith(".log"));
    }

    @Test
    @DisplayName("Only forbidden characters become empty string")
    void onlyForbiddenCharactersBecomeEmpty() {
        String input = "<>&;%`'\r\n";
        String result = sanitizer.sanitize(input);
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    @DisplayName("Emoji and non-letter/digit symbols are removed, letters/digits kept")
    void emojiAreRemovedLettersDigitsKept() {
        String input = "Report\uD83D\uDCC42025"; // "Report📄2025"
        String result = sanitizer.sanitize(input);
        assertEquals("Report2025", result);
    }

    @Test
    @DisplayName("Mixed slashes and backslashes are removed")
    void mixedSlashesBackslashesRemoved() {
        String input = "foo/bar\\baz";
        String result = sanitizer.sanitize(input);
        assertEquals("foobarbaz", result);
    }
}
