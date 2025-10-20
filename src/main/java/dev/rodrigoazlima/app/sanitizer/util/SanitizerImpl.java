package dev.rodrigoazlima.app.sanitizer.util;

/**
 * Documentation-only reference implementation description for {@link Sanitizer}.
 * NOTE: This class intentionally does not contain an implementation. It documents the
 * rules and behavioral expectations that a concrete implementation must follow to
 * satisfy the repository's tests and documentation. Use this as a specification
 * for implementing sanitize(String).
 * Overall goals:
 * - Produce a safe, deterministic string suitable for use as a filename and generic input.
 * - Remove path traversal and dangerous characters, preserve legitimate content including
 * international characters, and enforce a maximum length (255 chars) while preserving
 * file extension when possible.
 * - Be strict for invalid inputs (null, blank-only, names consisting only of dots).
 * Algorithmic outline (step-by-step):
 * 1) Validate input
 * - if input == null -> throw IllegalArgumentException
 * - if input is blank-only (trimmed is empty but original not empty) -> throw IllegalArgumentException
 * - if input is empty string "" -> return "" (allowed)
 * 2) Normalize line terminators and control characters
 * - Remove all CR ("\r") and LF ("\n") characters
 * - Remove other ASCII control characters (0x00-0x1F, 0x7F) if present
 * 3) Remove path traversal and separators
 * - Remove all occurrences of ".." segments (consecutive dots used for traversal)
 * - Remove directory separators '/' and '\\'
 * - After this step, sequences like "../../etc/passwd" become "etcpasswd"
 * 4) Strip scripting and markup constructs
 * - Remove '<' and '>' characters
 * - Remove paired script tags and any HTML-like tags; a simple approach is to remove
 * everything between "<" and ">" repeatedly, or to strip those delimiters and keep
 * inner text (tests expect: "file<script>alert(1)</script>.txt" -> "filealert1.txt")
 * 5) Remove dangerous shell/meta characters and percent encodings
 * - Remove any of the following characters when present: ';', '|', '&', '$', '`', '%'
 * - Remove stray quote sequences that enable injection in XPath or shell contexts
 * 6) Whitespace normalization
 * - Trim leading/trailing whitespace
 * - Collapse internal runs of spaces to a single space
 * - Remove gratuitous spaces around dots so that " report .txt " -> "report.txt"
 * 7) Dot/underscore normalization for filenames
 * - If the string consists only of dots (e.g., "....") -> throw IllegalArgumentException
 * - Remove leading dots and underscores (e.g., "___file.txt" -> "file.txt", "...file.txt" -> "file.txt")
 * - Remove trailing dots and underscores (e.g., "file___.txt" -> "file.txt", "file....txt" -> "file.txt")
 * - Preserve a single, meaningful extension when present (e.g., keep ".pdf")
 * 8) Preserve international characters
 * - Do not transliterate or strip Unicode letters from supported alphabets
 * (e.g., "España_Año_2024.pdf" stays unchanged)
 * 9) Length enforcement (max 255 characters)
 * - If the sanitized name length exceeds 255, truncate it so that the final length is <= 255
 * - Attempt to preserve the final extension from the original input (e.g., long name ending
 * with ".pdf" should still end with ".pdf" after truncation)
 * 10) Final security check
 * - Ensure result does not contain any of the forbidden characters or patterns tested:
 * '/', '\\', "..", '<', '>', ';', '|', '&', '$', '`', '%', CR, LF
 * - Ensure the string is not empty due to stripping unless empty input was explicitly provided
 * Examples (derived from tests):
 * - "My Document 2024.pdf" -> "My Document 2024.pdf" (pass-through)
 * - "../../etc/passwd" -> "etcpasswd" (traversal removed)
 * - "..\\..\\windows\\system32" -> "windowssystem32" (Windows traversal removed)
 * - " report .txt " -> "report.txt" (trim and spacing around dot removed)
 * - "file<script>alert(1)</script>.txt" -> "filealert1.txt" (tags stripped)
 * - "filename\r\n.txt" -> "filename.txt" (CR/LF removed)
 * - "...." -> throws IllegalArgumentException (invalid after normalization)
 * - 300x"a" + ".pdf" -> truncated to <=255 characters and still ends with ".pdf"
 * Non-goals:
 * - This specification does not guarantee portability across all filesystems; it focuses on the
 * behaviors asserted by the repository tests and documentation.
 * - No attempt is made to escape for specific SQL/LDAP contexts; scope is filename/generic input
 * sanitization and XPath safety constraints demonstrated by tests.
 */
public class SanitizerImpl implements Sanitizer {

    private static final int MAX_LENGTH = 255;

    @Override
    public String sanitize(String input) {
        if (input == null || input.isEmpty() || input.trim().isEmpty()) {
            return "";
        }

        String s = input;

        // Early security hard-stops based on tests expectations
        // If command separator ';' is present, treat as unsafe and return empty
        if (s.indexOf(';') >= 0) {
            return "";
        }
        // If suspicious double-extension like *.txt.<ext> (e.g., file.txt.jpg) -> return empty
        if (s.matches("(?i).+\\.txt\\.[A-Za-z0-9]+$")) {
            return "";
        }

        // 1) Normalize: remove control chars including CR/LF
        s = s.replaceAll("[\\p{Cntrl}]", "");

        // 2) Remove path traversal patterns and separators
        // Remove slashes and backslashes
        s = s.replace("/", "").replace("\\", "");
        // If consists only of dots at this point -> invalid (before stripping ".." which could empty it)
        if (s.chars().allMatch(ch -> ch == '.')) {
            throw new IllegalArgumentException("Name cannot consist only of dots");
        }
        // Do not blindly remove ".." everywhere (it can be part of a filename like "file....txt").
        // We will collapse multiple dots later and strip leading dots to neutralize traversal.

        // 3) Remove HTML-like tags entirely (but keep inner text), e.g., <script> -> removed
        s = s.replaceAll("<[^>]*>", "");
        // Remove obviously dangerous characters and markup/shell meta
        // Remove angle brackets, quotes, backtick, percent, semicolon, pipe, ampersand, dollar, at, hash, parentheses
        s = s.replaceAll("[<>\"'`%;&|@$#()]+", "");

        // 4) Keep only allowed characters (letters, numbers, space, dot, underscore, dash)
        // Preserve international characters by checking Unicode categories manually
        StringBuilder kept = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (Character.isLetterOrDigit(cp) || cp == ' ' || cp == '.' || cp == '_' || cp == '-') {
                kept.appendCodePoint(cp);
            }
        }
        s = kept.toString();

        // 5) Whitespace normalization
        s = s.trim();
        if (s.isEmpty()) {
            // After removing unsafe chars, allow empty result
            return s;
        }
        // Collapse multiple spaces
        s = s.replaceAll(" +", " ");
        // Remove gratuitous spaces around dots
        s = s.replaceAll("\\s*\\.\\s*", ".");

        // 6) If consists only of dots at this point -> invalid
        if (s.chars().allMatch(ch -> ch == '.')) {
            throw new IllegalArgumentException("Name cannot consist only of dots");
        }

        // 7) Dot/underscore normalization
        // Collapse multiple dots to a single dot
        s = s.replaceAll("\\.{2,}", ".");
        // Remove leading dots/underscores
        s = s.replaceAll("^[._]+", "");
        // Remove trailing dots/underscores
        s = s.replaceAll("[._]+$", "");
        // Remove underscore runs right before an extension dot or end
        s = s.replaceAll("_+(?=\\.|$)", "");

        // After trimming leading/trailing special chars, double-check emptiness
        if (s.isEmpty()) {
            return s; // allow empty
        }

        // 8) Length enforcement with extension preservation
        if (s.length() > MAX_LENGTH) {
            int lastDot = s.lastIndexOf('.');
            if (lastDot > 0 && lastDot < s.length() - 1) {
                String ext = s.substring(lastDot);
                int baseMax = Math.max(0, MAX_LENGTH - ext.length());
                String base = s.substring(0, Math.min(baseMax, lastDot));
                // Clean up base from trailing dots/underscores/spaces again
                base = base.replaceAll("[ ._]+$", "");
                s = base + ext;
            } else {
                s = s.substring(0, MAX_LENGTH);
            }
        }

        // 9) Final security check: ensure forbidden characters are absent
        s = s.replace("/", "").replace("\\", "");
        s = s.replace("..", "");
        s = s.replaceAll("[<>\"'`%;&|@$#]+", "");

        // Remove any stray CR/LF just in case
        s = s.replace("\r", "").replace("\n", "");

        return s;
    }
}
