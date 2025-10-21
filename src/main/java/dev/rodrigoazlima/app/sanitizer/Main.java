package dev.rodrigoazlima.app.sanitizer;

import dev.rodrigoazlima.app.sanitizer.impl.SanitizerImpl;

/**
 * Demo entry point for the xpath-sanitizer project.
 * This class wires a {@link SanitizerImpl} and sanitizes all command-line arguments,
 * concatenating the sanitized pieces and printing the result to standard output.
 * If no arguments are provided, it prints a short usage line.
 * Usage:
 *   java -jar target/xpath-sanitizer-1.0.0.jar <value1> [value2 ...]
 * Notes:
 * - Each argument is sanitized independently using {@link Sanitizer#sanitize(String)} and then concatenated.
 * - Arguments that sanitize to an empty string still contribute nothing to the final output; the final
 *   printed line will always end with a newline character ("\n").
 */
public class Main {
    /**
     * Program entry point. See class-level documentation for details.
     *
     * @param args the values to sanitize and concatenate; when null or empty, a usage line is printed
     */
    public static void main(String[] args) {
        Sanitizer sanitizer = new SanitizerImpl();

        if (args == null || args.length == 0) {
            System.out.println("Usage: java -jar xpath-sanitizer-1.0.0.jar <value1> [value2 ...]");
            return;
        }

        StringBuilder output = new StringBuilder();
        for (String arg : args) {
            String out = sanitizer.sanitize(arg);
            output.append(out);
        }
        System.out.println(output);
    }
}