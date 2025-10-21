package dev.rodrigoazlima.app.sanitizer;

import dev.rodrigoazlima.app.sanitizer.util.Sanitizer;
import dev.rodrigoazlima.app.sanitizer.util.SanitizerImpl;

public class Main {
    public static void main(String[] args) {
        Sanitizer sanitizer = new SanitizerImpl();

        if (args == null || args.length == 0) {
            System.out.println("Usage: java -jar xpath-sanitizer-1.0.0.jar <value1> [value2 ...]");
            return;
        }

        StringBuilder output = new StringBuilder("");
        for (String arg : args) {
            String out = sanitizer.sanitize(arg);
            output.append(out);
        }
        System.out.println(output);
    }
}