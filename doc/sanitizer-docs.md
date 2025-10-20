# SanitizerUtil Documentation

## Overview

`SanitizerUtil` is a utility class designed to sanitize user inputs and prevent common security vulnerabilities including XPath injection, path traversal, XSS attacks, and command injection.

**Version:** 1.0.0  
**Java Version:** 17+  
**Design Pattern:** Utility Pattern (static methods, non-instantiable)

---

## Table of Contents

1. [Purpose](#purpose)
2. [Security Threats Mitigated](#security-threats-mitigated)
3. [Dependencies](#dependencies)
4. [API Reference](#api-reference)
5. [Usage Examples](#usage-examples)
6. [Assumptions and Constraints](#assumptions-and-constraints)
7. [Security Considerations](#security-considerations)
8. [Testing](#testing)
9. [Best Practices](#best-practices)

---

## Purpose

This utility provides a single, well-tested entry point for sanitizing user inputs in security-critical contexts:

- **File Names**: Sanitize user-provided file names for safe storage
- **XPath Expressions**: Prevent XPath injection attacks in XML queries

> **Assumption**: This utility is designed for applications that need to accept user input for file names or use user input in XPath queries. It assumes the application has basic input validation in place at the controller/presentation layer.

---

## Security Threats Mitigated

### 1. XPath Injection
**Threat**: Malicious users can manipulate XPath queries to access unauthorized data or bypass authentication.

**Example Attack**:
```xpath
// Normal query
//user[username='john' and password='secret']

// Injected query
//user[username='' or '1'='1' and password='']
```

**Mitigation**: The utility uses OWASP Encoder to properly escape XPath special characters, preventing query manipulation.

> **Assumption**: The application uses XPath queries to interact with XML data sources. If using SQL databases, use PreparedStatements instead.

---

### 2. Path Traversal
**Threat**: Attackers can use special sequences like `../` to access files outside the intended directory.

**Example Attack**:
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
```

**Mitigation**: All path separators (`/`, `\`) and traversal sequences (`..`) are removed from file names.

> **Assumption**: File names are used for storage in a controlled directory structure. The application should still validate the final path before file operations.

---

### 3. Command Injection
**Threat**: Special characters can be used to execute arbitrary system commands if file names are used in shell operations.

**Example Attack**:
```
file.txt; rm -rf /
file.txt|whoami
$(malicious_command).txt
```

**Mitigation**: All command execution characters (`;`, `|`, `&`, `` ` ``, `$`) are removed.

> **Assumption**: File names may be used in file system operations. Applications should avoid passing file names directly to shell commands.

---

### 4. Cross-Site Scripting (XSS)
**Threat**: HTML/JavaScript can be embedded in file names to execute malicious scripts when displayed in web pages.

**Example Attack**:
```
<script>alert('XSS')</script>.pdf
<img src=x onerror=alert(1)>.jpg
```

**Mitigation**: Jsoup library strips all HTML tags from input.

> **Assumption**: File names may be displayed in web interfaces. Applications should still properly escape output when rendering file names in HTML.

---

### 5. Null Byte Injection
**Threat**: Null bytes can truncate file names in some systems, bypassing extension validation.

**Example Attack**:
```
malicious.php\0.jpg  // May be saved as malicious.php
```

**Mitigation**: All control characters including null bytes are removed.

> **Assumption**: The application runs on systems where null byte truncation could be exploited (primarily older systems).

---

## Dependencies

Add these dependencies to your `pom.xml`:

```xml
<!-- Apache Commons IO - File name utilities -->
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.15.1</version>
</dependency>

<!-- OWASP Java Encoder - Prevents XPath injection -->
<dependency>
    <groupId>org.owasp.encoder</groupId>
    <artifactId>encoder</artifactId>
    <version>1.2.3</version>
</dependency>

<!-- Jsoup - HTML sanitization -->
<dependency>
    <groupId>org.jsoup</groupId>
    <artifactId>jsoup</artifactId>
    <version>1.17.2</version>
</dependency>

<!-- JUnit Jupiter - Testing (test scope) -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.1</version>
    <scope>test</scope>
</dependency>
```

> **Assumption**: Maven is used as the build tool. For Gradle, convert dependencies accordingly.

---

## API Reference

### Main Method

```java
public static String sanitize(String input, SanitizationContext contextType)
```

**Parameters**:
- `input` (String): The user input to sanitize. Cannot be null.
- `contextType` (SanitizationContext): The context type for sanitization.

**Returns**: Sanitized string safe for the specified context.

**Throws**: 
- `IllegalArgumentException` if input is null, empty (for FILENAME), or invalid after sanitization.
- `UnsupportedOperationException` if attempting to instantiate the utility class.

---

### Sanitization Contexts

#### `SanitizationContext.FILENAME`

Sanitizes file names to ensure they contain only safe characters.

**Allowed Characters**:
- Letters (Unicode): `\p{L}` - Includes international characters (María, François, 文档, etc.)
- Numbers: `\p{N}` - 0-9 and Unicode numbers
- Spaces: For readability
- Dots (`.`): For file extensions
- Underscores (`_`): Common separator
- Hyphens (`-`): Common separator

**Removed Characters**:
- Path separators: `/`, `\`
- Path traversal: `..`
- Special characters: `@#$%^&*()+=[]{}|;:'",<>?`
- Control characters: Null bytes, newlines, carriage returns, tabs
- HTML tags: `<script>`, `<img>`, etc.

**Additional Processing**:
- Multiple consecutive spaces are replaced with a single space
- Leading/trailing special characters (dots, spaces, underscores, hyphens) are removed
- Maximum length enforced: 255 characters (truncates base name if needed)
- Extension is preserved during truncation

> **Assumption**: File names are limited to 255 characters, which is the standard limit for most file systems (NTFS, ext4, APFS). Some older systems may have lower limits (e.g., ISO 9660 has a 31 character limit).

**Example**:
```java
String safe = SanitizerUtil.sanitize("My Document 2024.pdf", FILENAME);
// Result: "My Document 2024.pdf"

String safe = SanitizerUtil.sanitize("../../etc/passwd", FILENAME);
// Result: "etcpasswd"
```

---

#### `SanitizationContext.XPATH`

Sanitizes strings for safe use in XPath expressions, preventing XPath injection attacks.

**How It Works**:
Uses OWASP Encoder's XML encoding to escape special characters:
- Single quotes (`'`) → `&apos;`
- Double quotes (`"`) → `&quot;`
- Less than (`<`) → `&lt;`
- Greater than (`>`) → `&gt;`
- Ampersand (`&`) → `&amp;`

**Security Note**: This encoding prevents XPath injection but the encoded string should still be used in parameterized XPath queries when possible.

> **Assumption**: The application constructs XPath queries dynamically using user input. If possible, prefer XPath libraries that support parameterized queries or precompiled expressions.

**Example**:
```java
String safe = SanitizerUtil.sanitize("O'Brien", XPATH);
// Result: "O&apos;Brien" (safe for XPath)

String safe = SanitizerUtil.sanitize("' or '1'='1", XPATH);
// Result: "&apos; or &apos;1&apos;=&apos;1" (attack prevented)
```

---

## Usage Examples

### Example 1: File Upload Endpoint

```java
@RestController
@RequestMapping("/api/files")
public class FileUploadController {

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(
            @RequestParam("file") MultipartFile file) {
        
        try {
            // Get original filename from user
            String originalFilename = file.getOriginalFilename();
            
            // Sanitize the filename
            String safeFilename = SanitizerUtil.sanitize(
                originalFilename, 
                SanitizationContext.FILENAME
            );
            
            // Save file with sanitized name
            Path filePath = Paths.get(UPLOAD_DIR, safeFilename);
            file.transferTo(filePath.toFile());
            
            return ResponseEntity.ok("File uploaded: " + safeFilename);
            
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body("Invalid filename: " + e.getMessage());
        }
    }
}
```

> **Assumption**: The application has a dedicated upload directory (`UPLOAD_DIR`) that is not web-accessible. The application should also validate file size, content type, and scan for malware.

---

### Example 2: User Profile with International Names

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @PutMapping("/{id}/avatar")
    public ResponseEntity<String> updateAvatar(
            @PathVariable Long id,
            @RequestParam("avatar") MultipartFile avatar) {
        
        try {
            // Sanitize filename preserving international characters
            String filename = SanitizerUtil.sanitize(
                avatar.getOriginalFilename(),
                SanitizationContext.FILENAME
            );
            
            // Generate unique filename
            String uniqueFilename = id + "_" + System.currentTimeMillis() 
                + "_" + filename;
            
            // Save avatar
            saveAvatar(uniqueFilename, avatar);
            
            return ResponseEntity.ok("Avatar updated: " + filename);
            
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body("Invalid filename: " + e.getMessage());
        }
    }
}
```

> **Assumption**: The application stores avatars with a unique identifier to prevent filename collisions. Multiple users may upload files with the same name.

---

### Example 3: XPath Query with User Input

```java
@Service
public class UserXmlService {

    private final DocumentBuilder documentBuilder;

    public User findUserByUsername(String username) {
        try {
            // Sanitize username for XPath
            String safeUsername = SanitizerUtil.sanitize(
                username, 
                SanitizationContext.XPATH
            );
            
            // Build XPath query (still vulnerable if not careful!)
            // BETTER: Use XPath with proper binding
            String xpathExpression = "//user[username='" + safeUsername + "']";
            
            // Execute query
            XPath xpath = XPathFactory.newInstance().newXPath();
            Node userNode = (Node) xpath.evaluate(
                xpathExpression, 
                xmlDocument, 
                XPathConstants.NODE
            );
            
            return parseUser(userNode);
            
        } catch (Exception e) {
            throw new RuntimeException("Error querying user", e);
        }
    }
}
```

> **Assumption**: The application uses XPath for querying XML data. This example shows basic sanitization, but applications should prefer XML libraries that support parameterized queries or proper XPath variable binding for maximum security.

---

### Example 4: Batch File Processing

```java
@Service
public class BatchFileProcessor {

    public List<String> processBatch(List<String> filenames) {
        List<String> safeFilenames = new ArrayList<>();
        
        for (String filename : filenames) {
            try {
                String safe = SanitizerUtil.sanitize(
                    filename,
                    SanitizationContext.FILENAME
                );
                safeFilenames.add(safe);
                
            } catch (IllegalArgumentException e) {
                // Log invalid filename
                logger.warn("Skipping invalid filename: {}", filename, e);
            }
        }
        
        return safeFilenames;
    }
}
```

> **Assumption**: The application processes multiple files and needs to handle some invalid filenames gracefully without failing the entire batch.

---

## Assumptions and Constraints

### 1. Input Validation Assumption
> **Assumption**: The application performs basic input validation at the controller/presentation layer before calling this utility. This utility is a defense-in-depth measure, not the only line of defense.

### 2. Character Encoding Assumption
> **Assumption**: The application uses UTF-8 encoding throughout. File names with Unicode characters require UTF-8 support in the file system and application server.

### 3. File System Assumption
> **Assumption**: The underlying file system supports Unicode file names and has a 255-character limit. Some older systems (FAT32, ISO 9660) have more restrictive limits.

### 4. Extension Validation Assumption
> **Assumption**: The application validates file extensions separately. This utility does NOT validate whether `.exe`, `.sh`, or other executable extensions are safe. Implement a whitelist of allowed extensions.

```java
// Additional extension validation recommended
private static final Set<String> ALLOWED_EXTENSIONS = 
    Set.of("pdf", "jpg", "jpeg", "png", "doc", "docx", "txt");

public boolean isAllowedExtension(String filename) {
    String extension = FilenameUtils.getExtension(filename).toLowerCase();
    return ALLOWED_EXTENSIONS.contains(extension);
}
```

### 5. Content Validation Assumption
> **Assumption**: The application validates file content separately. A file named `document.pdf` might actually contain executable code. Use content-type validation and malware scanning.

### 6. Storage Path Assumption
> **Assumption**: Sanitized file names are stored in a controlled directory structure. The application should construct full paths safely:

```java
// SAFE: Using Path API prevents traversal
Path basePath = Paths.get(UPLOAD_DIR).toRealPath();
Path filePath = basePath.resolve(sanitizedFilename).normalize();

// Verify path is still within base directory
if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

### 7. Concurrent Access Assumption
> **Assumption**: The utility methods are thread-safe as they are stateless. However, file operations using sanitized names should handle race conditions (e.g., duplicate filenames).

### 8. XPath Library Assumption
> **Assumption**: The XPath sanitization is compatible with standard Java XPath libraries (javax.xml.xpath). Different XML parsing libraries may have different escaping requirements.

### 9. Error Handling Assumption
> **Assumption**: The application handles `IllegalArgumentException` appropriately. Invalid input should not crash the application but should be logged and reported to users with safe error messages.

### 10. Performance Assumption
> **Assumption**: Sanitization adds minimal overhead (typically <1ms per operation). For high-throughput applications processing millions of files, consider caching sanitized names if the same names are processed repeatedly.

---

## Security Considerations

### Defense in Depth

This utility is ONE layer of defense. A complete security strategy includes:

1. **Input Validation**: Validate at the controller layer (length, format, required fields)
2. **Sanitization**: Use this utility to clean dangerous characters
3. **Output Encoding**: Escape data when displaying in HTML/JSON
4. **Authorization**: Verify user has permission to upload/access files
5. **Content Validation**: Verify file content matches extension
6. **Malware Scanning**: Scan uploaded files for viruses
7. **Rate Limiting**: Prevent abuse of file upload endpoints
8. **Storage Isolation**: Store uploaded files outside the web root

> **Assumption**: The application implements multiple security layers. Relying solely on filename sanitization is insufficient.

---

### Known Limitations

#### 1. Unicode Homograph Attacks
File names like `аdmin.txt` (using Cyrillic 'а') look like `admin.txt` but are different files.

**Mitigation**: Consider normalizing Unicode or restricting to ASCII if international characters are not needed.

> **Assumption**: The application accepts international user names and file names. If your application is English-only, consider restricting to ASCII characters.

#### 2. File Name Collisions
Multiple users might upload files with the same name after sanitization.

**Example**:
- User 1 uploads: `My@Document#2024.pdf`
- User 2 uploads: `My Document 2024.pdf`
- Both sanitize to: `My Document 2024.pdf`

**Mitigation**: Append unique identifiers (user ID, timestamp, UUID) to filenames.

```java
String uniqueFilename = userId + "_" + System.currentTimeMillis() 
    + "_" + sanitizedFilename;
```

> **Assumption**: The application handles filename uniqueness at a higher level. This utility does not generate unique filenames.

#### 3. Case Sensitivity
Some file systems are case-insensitive (Windows, macOS default), others are case-sensitive (Linux).

**Example**:
- `File.txt` and `file.txt` may be the same file on Windows
- But different files on Linux

**Mitigation**: Store a lowercase version for comparison if uniqueness is critical.

> **Assumption**: The application may run on different operating systems. Test file handling on all target platforms.

#### 4. Timing Attacks
Sanitization time varies based on input length and content complexity.

**Impact**: In highly sensitive applications, timing differences could leak information about input validation.

**Mitigation**: For cryptographic operations, use constant-time comparisons.

> **Assumption**: This utility is not designed for cryptographic operations where timing attacks are a concern.

---

## Testing

The utility includes comprehensive unit tests covering:

- ✅ Valid inputs (clean filenames, international characters)
- ✅ Invalid inputs (null, empty, special characters)
- ✅ Security attacks (XSS, path traversal, command injection, XPath injection)
- ✅ Edge cases (long filenames, multiple extensions, control characters)
- ✅ International characters (Spanish, French, German, Portuguese, Chinese, Japanese, Arabic, Cyrillic)

### Running Tests

```bash
mvn test
```

### Test Coverage

> **Assumption**: The application maintains >90% code coverage for security-critical utilities. Use tools like JaCoCo to verify coverage.

```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.11</version>
</plugin>
```

---

## Best Practices

### 1. Always Validate Before Sanitizing

```java
// BAD: Sanitize without validation
String safe = SanitizerUtil.sanitize(userInput, FILENAME);

// GOOD: Validate first
if (userInput == null || userInput.length() > 200) {
    throw new IllegalArgumentException("Invalid input");
}
String safe = SanitizerUtil.sanitize(userInput, FILENAME);
```

### 2. Use Try-Catch for Error Handling

```java
try {
    String safe = SanitizerUtil.sanitize(filename, FILENAME);
    // Process file
} catch (IllegalArgumentException e) {
    logger.error("Invalid filename: {}", filename, e);
    return ResponseEntity.badRequest()
        .body("Please provide a valid filename");
}
```

### 3. Log Sanitization Events

```java
String original = userInput;
String sanitized = SanitizerUtil.sanitize(original, FILENAME);

if (!original.equals(sanitized)) {
    logger.warn("Filename was sanitized. Original: {}, Sanitized: {}", 
        original, sanitized);
}
```

> **Assumption**: Suspicious input patterns should be logged for security monitoring. Consider integrating with SIEM systems for real-time threat detection.

### 4. Whitelist File Extensions

```java
String sanitized = SanitizerUtil.sanitize(filename, FILENAME);
String extension = FilenameUtils.getExtension(sanitized).toLowerCase();

if (!ALLOWED_EXTENSIONS.contains(extension)) {
    throw new IllegalArgumentException("File type not allowed: " + extension);
}
```

### 5. Generate Unique File Names

```java
String sanitized = SanitizerUtil.sanitize(filename, FILENAME);
String baseName = FilenameUtils.getBaseName(sanitized);
String extension = FilenameUtils.getExtension(sanitized);

String uniqueName = String.format("%s_%s_%d.%s",
    userId,
    baseName,
    System.currentTimeMillis(),
    extension
);
```

### 6. Store Metadata Separately

```java
@Entity
public class FileMetadata {
    private String internalFilename;  // Sanitized + unique
    private String originalFilename;  // User's original name
    private String uploadedBy;
    private LocalDateTime uploadedAt;
    private String contentType;
    private Long fileSize;
}
```

> **Assumption**: Applications should maintain a database record of file metadata, including the original user-provided filename for display purposes.

### 7. Implement File Size Limits

```java
private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

if (file.getSize() > MAX_FILE_SIZE) {
    throw new IllegalArgumentException("File too large");
}
```

### 8. Scan for Malware

```java
// Pseudo-code - use actual antivirus library
if (!antivirusScanner.isSafe(file)) {
    throw new SecurityException("Malware detected in file");
}
```

> **Assumption**: Applications accepting file uploads should integrate with antivirus/anti-malware solutions, especially for publicly accessible endpoints.

---

## Troubleshooting

### Issue: Filename too short after sanitization

**Cause**: Input contained mostly special characters that were removed.

**Solution**: Validate minimum length before sanitization or generate a default name.

```java
try {
    return SanitizerUtil.sanitize(filename, FILENAME);
} catch (IllegalArgumentException e) {
    return "file_" + System.currentTimeMillis() + ".dat";
}
```

---

### Issue: International characters not preserved

**Cause**: Database or file system doesn't support UTF-8.

**Solution**: Ensure UTF-8 encoding everywhere:

```properties
# application.properties
spring.datasource.url=jdbc:mysql://localhost:3306/db?characterEncoding=UTF-8
server.servlet.encoding.charset=UTF-8
server.servlet.encoding.force=true
```

---

### Issue: XPath queries still failing after sanitization

**Cause**: XPath library may need additional escaping or the query structure is wrong.

**Solution**: Use XPath variables/parameters instead of string concatenation:

```java
// BETTER APPROACH
XPathExpression expr = xpath.compile("//user[username=$username]");
// Set variable $username to sanitized value
```

> **Assumption**: Modern XPath libraries support parameterized queries. Check your XML library documentation for the proper way to bind variables.

---

## Changelog

### Version 1.0.0 (2024-10-20)
- Initial release
- Support for FILENAME and XPATH contexts
- Comprehensive security protections
- Full Unicode support
- Complete unit test coverage

---

## License

This utility is provided as-is for use in Spring Boot applications. Ensure all dependencies comply with your organization's licensing requirements.

---

## Support

For issues, questions, or contributions, please contact your development team or security officer.

> **Assumption**: This utility is maintained as part of your internal codebase. Organizations should designate a team member responsible for security updates and dependency management.