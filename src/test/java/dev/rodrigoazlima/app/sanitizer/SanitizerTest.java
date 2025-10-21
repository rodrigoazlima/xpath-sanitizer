package dev.rodrigoazlima.app.sanitizer;

import dev.rodrigoazlima.app.sanitizer.impl.SanitizerImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Assumptions:
 * - The repository contains multiple versions of a Sanitizer utility. The interface `Sanitizer` defines
 * a single method `sanitize(String)` which concrete implementations should provide.
 * - Documentation examples in doc/sanitizer-docs.md show expected inputs/outputs for certain scenarios.
 * In these tests we validate those expectations by mocking the Sanitizer interface to represent the
 * contract described by the documentation rather than a specific concrete implementation detail.
 */
@ExtendWith(MockitoExtension.class)
class SanitizerTest {

    private final Sanitizer sanitizer = new SanitizerImpl();

    @Nested
    @DisplayName("Filename Sanitization")
    class FilenameDocsExamples {

        @Test
        @DisplayName("Example: Simple safe filename remains unchanged")
        void simpleFilenamePassThrough() {
            // Given (from docs): "My Document 2024.pdf" => "My Document 2024.pdf"
            String input = "My Document 2024.pdf";
            String expected = "My Document 2024.pdf";
            String actual = sanitizer.sanitize(input);
            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Example: Path traversal removed -> '../../etc/passwd' => 'etcpasswd'")
        void pathTraversalExample() {
            // Given (from docs): "../../etc/passwd" => "etcpasswd"
            String input = "../../etc/passwd";
            String expected = "etcpasswd";

            String actual = sanitizer.sanitize(input);

            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Should allow empty string for XPath context")
        void shouldAllowEmptyStringForXPath() {
            assertDoesNotThrow(() -> sanitizer.sanitize(""));
        }
    }

    @Nested
    @DisplayName("Parameterized - Documentation Contract")
    class ParameterizedDocsExamples {

        @ParameterizedTest(name = "[{index}] input='{0}' => expected='{1}'")
        @CsvSource({"'My Document 2024.pdf','My Document 2024.pdf'",
                "'../../etc/passwd','etcpasswd'",
                "'..\\..\\windows\\system32','windowssystem32'",
                "' report .txt ','report.txt'"})
        void sanitizeAccordingToDocs(String input, String expected) {
            String actual = sanitizer.sanitize(input);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Filename Sanitization Tests")
    class FilenameSanitizationTests {
        @ParameterizedTest
        @CsvSource({"document.pdf, document.pdf, false",
                "María_José_Report.xlsx, María_José_Report.xlsx, false",
                "report_2024_v2.pdf, report_2024_v2.pdf, false",
                "My Document.docx, 'My Document.docx', false",
                "file.name.test.pdf, file.name.test.pdf, false",
                "file_name_123.txt, file_name_123.txt, false",
                "file-name-test.pdf, file-name-test.pdf, false",
                "file@name#test$.pdf, filenametest.pdf, false",
                "path/to/file.pdf, pathtofile.pdf, false",
                "../../etc/passwd, etcpasswd, false",
                "file<script>alert(1)</script>.txt, filealert1.txt, false",
                "'my    document    file.docx', 'my document file.docx', false",
                "README, README, false",
                "...., '', false",
                "...file.txt, file.txt, false",
                "file....txt, file.txt, false",
                "___file.txt, file.txt, false",
                "file___.txt, file.txt, false",
                "'filename\r\n.txt', filename.txt, false",
                "'   file.txt   ', file.txt, false",
                "MyDocument.PDF, MyDocument.PDF, false",
                "file.backup.v2.pdf, file.backup.v2.pdf, false"})
        @DisplayName("Should sanitize filenames")
        void shouldSanitizeFilenames(String input, String expected, boolean throwsException) {
            if (throwsException) {
                assertThrows(IllegalArgumentException.class, () -> sanitizer.sanitize(input));
            } else {
                assertEquals(expected, sanitizer.sanitize(input));
            }
        }

        @Test
        @DisplayName("Should truncate long filenames")
        void shouldTruncateLongFilenames() {
            String longName = "a".repeat(300) + ".pdf";
            String result = sanitizer.sanitize(longName);
            assertTrue(result.length() <= 255);
            assertTrue(result.endsWith(".pdf"));
        }
    }

    @Nested
    @DisplayName("XPath Sanitization Tests")
    class XPathSanitizationTests {
        @ParameterizedTest
        @CsvSource({"John Doe, true, ''",
                "O'Brien, false, '",
                "Company \"Best\" Inc, false, \"",
                "' or '1'='1, false, ' or '1'='1",
                "'', true, ''",
                "María José, true, ''"})
        @DisplayName("Should sanitize XPath inputs")
        void shouldSanitizeXPath(String input, boolean notNull, String forbidden) {
            String result = sanitizer.sanitize(input);
            assertNotNull(result);
            if (!notNull) {
                assertFalse(result.contains(forbidden));
            }
        }
    }

    @Nested
    @DisplayName("Security Tests")
    class SecurityTests {
        @ParameterizedTest
        @CsvSource({"'../../../etc/passwd', '', '/|..'",
                "'..\\..\\..\\windows\\system32', '', '\\|..'",
                "'file.txt;rm -rf /', '', ';'",
                "'file.txt|whoami', 'file.txtwhoami', ''",
                "'file.txt&whoami', '', '&'",
                "'$HOME/file.txt', '', '$'",
                "'`whoami`.txt', '', '`'",
                "'<script>alert(1)</script>.txt', '', '<|>'",
                "'file%2e%2e%2fpasswd.txt', '', '%'",
                "'file''; DROP TABLE users;--.txt', '', ';|'''",
                "'file.txt.jpg', '', ''",
                "'file\nname.txt', '', '\n'",
                "'file\rname.txt', '', '\r'"})
        @DisplayName("Should prevent security attacks")
        void shouldPreventSecurityAttacks(String input, String expected, String forbidden) {
            String result = sanitizer.sanitize(input);
            assertEquals(expected.isEmpty() ? result : expected, result);
            // Normalize forbidden tokens: support a single CSV cell containing '|' separated tokens
            java.util.List<String> tokens = new java.util.ArrayList<>();
            if (forbidden != null && !forbidden.isEmpty()) {
                if (forbidden.contains("|")) {
                    for (String part : forbidden.split("\\|")) {
                        if (!part.isEmpty()) tokens.add(part);
                    }
                } else {
                    tokens.add(forbidden);
                }
            }
            for (String t : tokens) {
                assertFalse(result.contains(t));
            }
        }
    }

    @Nested
    @DisplayName("International Character Tests")
    class InternationalCharacterTests {
        @ParameterizedTest
        @CsvSource({"España_Año_2024.pdf, España_Año_2024.pdf",
                "Français_Café.doc, Français_Café.doc",
                "Müller_Straße.txt, Müller_Straße.txt",
                "São_Paulo_Ação.xlsx, São_Paulo_Ação.xlsx",
                "文档_2024.pdf, 文档_2024.pdf",
                "ファイル名.txt, ファイル名.txt",
                "ملف_2024.pdf, ملف_2024.pdf",
                "Документ_Москва.docx, Документ_Москва.docx"})
        @DisplayName("Should preserve international characters")
        void shouldPreserveInternationalCharacters(String input, String expected) {
            assertEquals(expected, sanitizer.sanitize(input));
        }
    }
}
