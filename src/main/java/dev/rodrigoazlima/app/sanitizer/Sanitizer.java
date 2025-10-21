package dev.rodrigoazlima.app.sanitizer;

/**
 * Contract for input sanitization used across the application.
 *
 * Behavior and rules are derived from the repository documentation (doc/sanitizer-docs.md)
 * and the executable specification provided by tests in:
 * - src/test/java/dev/rodrigoazlima/app/sanitizer/SanitizerTest.java
 *
 * High-level contract (summarized):
 * - Single responsibility: provide a safe, deterministic transformation of potentially unsafe input.
 * - Deterministic: same input always yields the same output.
 * - Non-throwing for normal cases, but must validate inputs and throw IllegalArgumentException for
 *   invalid cases as described below.
 * - Internationalization: preserve valid international (Unicode) letters and common filename characters.
 *
 * Input validation:
 * - null: must throw IllegalArgumentException.
 * - Blank-only strings (consisting only of spaces or control characters): must throw IllegalArgumentException.
 * - Empty string: allowed in contexts like XPath per tests; since the public API does not expose
 *   context, the expected behavior is to allow empty string and return an empty safe result.
 *
 * Filename-oriented sanitization rules expected by tests (examples in tests act as specification):
 * - Safe inputs pass through unchanged (e.g., "My Document 2024.pdf" -> same).
 * - Remove path traversal and separators: '/', '\\', and ".." segments are removed so that
 *   "../../etc/passwd" -> "etcpasswd", and "..\\..\\windows\\system32" -> "windowssystem32".
 * - Remove disallowed metacharacters including but not limited to: < > ; & $ ` % and scripting tags
 *   (e.g., "file<script>alert(1)</script>.txt" -> "filealert1.txt").
 * - Normalize whitespace: trim leading/trailing whitespace, collapse internal runs of spaces to a single
 *   space, and remove gratuitous spaces around dots (e.g., " report .txt " -> "report.txt").
 * - Dot/underscore normalization: excessive leading/trailing dots/underscores are removed so that
 *   "...." is invalid (IllegalArgumentException), "___file.txt" -> "file.txt", "file___.txt" -> "file.txt",
 *   "file....txt" -> "file.txt", and "...file.txt" -> "file.txt".
 * - Newlines and carriage returns are removed (e.g., "filename\r\n.txt" -> "filename.txt").
 * - Multiple extensions are handled conservatively; examples indicate collapsing to a sane single extension
 *   or base name while preserving a valid final extension when possible (e.g., "file.txt.jpg" -> sanitized
 *   name without forbidden patterns; see Security tests expectations).
 * - Length limit: output length must be <= 255 characters; if truncated, the final extension from the input
 *   should be preserved where possible (test ensures long names end with ".pdf").
 * - International characters are preserved (e.g., "España_Año_2024.pdf" remains unchanged).
 *
 * Security-focused sanitization expectations (from Security tests):
 * - Remove or neutralize shell metacharacters (; | & $ `) and percent-encoded attack patterns (%).
 * - Strip angle brackets to mitigate HTML/script injection.
 * - Remove CR/LF characters ("\r", "\n").
 * - After sanitization, result must not contain any of the forbidden characters present in test cases.
 *
 * XPath-related expectations (from XPath tests):
 * - Method should produce a non-null output for typical names and allow empty input.
 * - Quotes in the input should be handled so that obvious injection fragments (e.g., "' or '1'='1")
 *   do not survive in the sanitized output as literal sequences.
 */
public interface Sanitizer {

    /**
     * Sanitizes user input according to the documented rules.
     * This is the single public entry point for all sanitization operations.
     *
     * Validation:
     * - null -> IllegalArgumentException
     * - blank-only -> IllegalArgumentException
     * - empty string -> allowed, returns empty safe string
     *
     * Examples (derived from tests):
     * - "My Document 2024.pdf" -> "My Document 2024.pdf"
     * - "../../etc/passwd" -> "etcpasswd"
     * - "..\\..\\windows\\system32" -> "windowssystem32"
     * - " report .txt " -> "report.txt"
     * - "file<script>alert(1)</script>.txt" -> "filealert1.txt"
     * - "filename\r\n.txt" -> "filename.txt"
     * - too-long name of 300 'a' + ".pdf" -> truncated to <=255 chars and still ends with ".pdf"
     *
     * @param input the input to sanitize
     * @return a sanitized String that conforms to the rules above
     * @throws IllegalArgumentException if input is null or blank-only, or for cases like a name consisting
     *                                  only of dots that the rules deem invalid (see tests)
     */
    String sanitize(String input);

}
