# xpath-sanitizer

Java utilities to sanitize Strings to mitigate XPath injection and related input risks (path traversal, XSS-in-filenames, command separators), with examples and tests.

## Overview
This repository provides a small, focused sanitizer utility intended for use anywhere you accept user-controlled text that will be used in sensitive contexts (e.g., file names or XPath queries). It includes:
- A simple `Sanitizer` interface and a reference `SanitizerImpl` implementation
- A tiny demo `Main` entry point
- Documentation with examples in the `doc/` folder
- JUnit 5 tests validating behavior

See also:
- doc/sanitizer-docs.md — detailed documentation, assumptions, and examples
- doc/xpath-vulnerabilities.md — background on XPath injection risks

## Tech stack
- Language: Java 17
- Build tool / package manager: Maven (pom.xml)
- Testing: JUnit 5 (Jupiter), Mockito
- Libraries used (from pom.xml): Apache Commons IO, Apache Commons Text, OWASP Encoder, jsoup

## Requirements
- Java 17 or newer (JDK)
- Maven 3.9+ (or a recent Maven provided by your IDE)
- Internet access to resolve Maven dependencies

## Project structure
```
xpath-sanitizer
├─ pom.xml                              # Maven project configuration
├─ README.md                            # This file
├─ doc\
│  ├─ sanitizer-docs.md                 # Detailed sanitizer documentation and examples
│  └─ xpath-vulnerabilities.md          # Background on XPath vulnerabilities
├─ src\main\java\
│  ├─ com\example\demo\Main.java       # Demo entry point
│  └─ com\example\demo\util\
│     ├─ Sanitizer.java                 # Public API (interface)
│     └─ SanitizerImpl.java             # Reference implementation (see notes in code)
├─ src\main\resources\
│  ├─ junit-platform.properties         # JUnit platform configuration (used by tests)
│  └─ META-INF\services\org.junit.jupiter.api.extension.Extension
│                                        # Auto-registered JUnit 5 extension(s)
└─ src\test\java\com\example\demo\
   └─ SanitizerTest.java                # Unit tests covering filenames, XPath, security, i18n
```

## Build
Use Maven to build the project.

- Clean and compile:
  - Windows PowerShell:
    - mvn -v         # verify Maven
    - mvn clean compile

- Full build with tests:
  - mvn clean verify

- Package JAR (non-executable by default; see TODO below):
  - mvn clean package
  - Output: target\xpath-sanitizer-1.0.0.jar (groupId: dev.rodrigoazlima.app.sanitizer)

## Run
This project includes a simple demo main class at `dev.rodrigoazlima.app.sanitizer.Main` that prints a message and constructs `SanitizerImpl`.

Because the current Maven JAR plugin manifest points to a non-existent main class, the packaged JAR is not executable yet. You can still run the main class directly from compiled classes:

- Compile: mvn -q compile
- Run via java -cp:
  - Windows PowerShell:
    - java -cp target\classes dev.rodrigoazlima.app.sanitizer.Main

TODO:
- Fix the JAR manifest mainClass in pom.xml (currently set to `com.exemplo.app.App`, which does not exist). Suggested value: `dev.rodrigoazlima.app.sanitizer.Main`.
- Optionally add the Maven Exec Plugin for `mvn exec:java -Dexec.mainClass=dev.rodrigoazlima.app.sanitizer.Main` convenience.

## Usage (library)
If you intend to use this as a library within another project after packaging, depend on the produced artifact or copy the utility class. Example code:

```java
import dev.rodrigoazlima.app.sanitizer.Sanitizer;
import dev.rodrigoazlima.app.sanitizer.SanitizerImpl;

Sanitizer sanitizer = new SanitizerImpl();
String safe = sanitizer.sanitize(userInput);
```

See `doc/sanitizer-docs.md` for detailed expectations and examples.

## Scripts and common commands
Maven lifecycle commands you may find useful:
- mvn clean                 # remove build outputs
- mvn test                  # run unit tests
- mvn verify                # run tests and integration checks
- mvn -DskipTests package   # build JAR under target/
- mvn package               # same as above but runs tests

Optional (after adding Exec Plugin):
- mvn exec:java -Dexec.mainClass=dev.rodrigoazlima.app.sanitizer.Main

## Configuration and environment variables
- No required environment variables at this time.
- TODO: Document any configuration knobs once introduced (e.g., max filename length, allowed character sets). If such settings are made configurable via system properties or env vars in the future, list them here with defaults and examples.

## Testing
Run the JUnit 5 test suite with Maven:
- mvn test

Tips:
- Run a single test class: mvn -Dtest=SanitizerTest test

What’s covered:
- Filename sanitization (preserve acceptable characters, collapse whitespace, remove traversal, enforce max length)
- XPath-oriented sanitization expectations (quotes, special chars)
- Security edges (command separators, HTML tags, encoding variants)
- International characters preservation

Notes:
- Tests assume behavior documented in doc/sanitizer-docs.md. If you change sanitization rules, update tests and docs together.

## Known issues / TODOs
- The packaged JAR is not executable: pom.xml manifest `mainClass` points to `com.exemplo.app.App` (missing). Update to `dev.rodrigoazlima.app.sanitizer.Main` or another real entry point.
- No license file present in the repository.
- Some docs may describe additional utility shapes (e.g., static utility style) — align implementation and docs as needed.

## License
No explicit license file is present in this repository.

TODO:
- Add a LICENSE file (e.g., MIT, Apache-2.0, or your preferred license) and update this section accordingly.

---

Last updated: 2025-10-20 15:26 (local)
