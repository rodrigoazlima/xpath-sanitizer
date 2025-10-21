# xpath-sanitizer

Utilities for sanitizing strings to mitigate XPath injection and related input risks (path traversal, XSS-in-filenames, command separators). Includes documentation and tests.

## Overview
This repository provides a focused sanitizer intended for situations where user-controlled text is used in sensitive contexts (e.g., file names or XPath queries). It includes:
- A simple `Sanitizer` interface and a reference `SanitizerImpl` implementation
- A small demo entry point (`Main`)
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
├─ LICENSE                                   # MIT License
├─ pom.xml                                   # Maven project configuration
├─ README.md                                 # This file
├─ doc\
│  ├─ sanitizer-docs.md                      # Detailed sanitizer documentation and examples
│  └─ xpath-vulnerabilities.md               # Background on XPath vulnerabilities
├─ src\main\java\dev\rodrigoazlima\app\sanitizer\
│  ├─ Main.java                              # Demo entry point
│  ├─ Sanitizer.java                         # Public API (interface)
│  └─ impl\
│     └─ SanitizerImpl.java                  # Reference implementation
└─ src\test\java\dev\rodrigoazlima\app\sanitizer\
   ├─ MainTest.java                          # Basic CLI/main behavior tests
   └─ SanitizerTest.java                     # Unit tests (filenames, XPath, security, i18n)
```

## Setup and build
Use Maven to build the project.

- Verify Java/Maven and compile:
  - mvn -v
  - mvn clean compile

- Run tests:
  - mvn test

- Full build with tests and checks:
  - mvn clean verify

- Package executable JAR (with manifest pointing to Main):
  - mvn clean package
  - Output: target\xpath-sanitizer-1.0.0.jar

## Run
There is a demo main class at `dev.rodrigoazlima.app.sanitizer.Main`.

- Run from the packaged JAR (after packaging):
  - java -jar target\xpath-sanitizer-1.0.0.jar <value1> [value2 ...]

- Run from compiled classes (without packaging):
  - java -cp target\classes dev.rodrigoazlima.app.sanitizer.Main <value1> [value2 ...]

Tip (optional): you may add the Maven Exec Plugin for the convenience command
`mvn exec:java -Dexec.mainClass=dev.rodrigoazlima.app.sanitizer.Main`.

## Usage as a library
If you intend to use this as a library within another project after packaging, depend on the produced artifact or copy the utility class. Example code:

```java
import dev.rodrigoazlima.app.sanitizer.Sanitizer;
import dev.rodrigoazlima.app.sanitizer.impl.SanitizerImpl;

Sanitizer sanitizer = new SanitizerImpl();
String safe = sanitizer.sanitize(userInput);
```

See `doc/sanitizer-docs.md` for detailed expectations and examples.

## Scripts and common commands
Maven lifecycle commands you may find useful:
- mvn clean                       # remove build outputs
- mvn test                        # run unit tests
- mvn verify                      # run tests and integration checks
- mvn -Dtest=SanitizerTest test   # run a single test class
- mvn -DskipTests package         # build JAR under target/
- mvn package                     # same as above but runs tests

## Configuration and environment variables
- No required environment variables at this time.
- TODO: If configuration knobs are introduced (e.g., max filename length, allowed character sets), document their env vars/system properties here with defaults and examples.

## Testing
Run the JUnit 5 test suite with Maven:
- mvn test

What’s covered by tests:
- Filename sanitization (preserve acceptable characters, collapse whitespace, remove traversal, enforce max length)
- XPath-oriented sanitization expectations (quotes, special chars)
- Security edges (command separators, HTML tags, percent encodings)
- International characters preservation

Notes:
- Tests assert behaviors aligned with doc/sanitizer-docs.md. If you change sanitization rules, update tests and docs together.

## License
MIT License © 2025 Rodrigo Lima — see LICENSE for full text.

## Known issues / TODOs

---

Last updated: 2025-10-21 05:11 (local)
