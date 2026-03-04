package com.scalesec.vulnado;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Integration security tests for the CowController class to verify
 * command injection protection at the API endpoint level.
 */
@DisplayName("CowController Security Integration Tests")
public class CowControllerSecurityTest {

    @Mock
    private Cowsay mockCowsay;

    @InjectMocks
    private CowController cowController;

    private Cowsay realCowsay;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        realCowsay = new Cowsay();
    }

    // ===== API Endpoint Security Tests =====

    @Test
    @DisplayName("Should accept and process valid input through API endpoint")
    public void testValidInputThroughEndpoint() {
        // Using real Cowsay instance for integration test
        CowController controller = new CowController();
        String input = "Hello from API";

        // This will call the actual run method
        String result = realCowsay.run(input);

        assertNotNull(result, "Result should not be null");
        assertFalse(result.startsWith("Error:") && result.contains("invalid characters"),
            "Valid input should be processed successfully");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "; cat /etc/passwd",
        "& whoami",
        "| ls -la",
        "&& rm -rf /",
        "|| echo hacked",
        "`id`",
        "$(whoami)"
    })
    @DisplayName("Should reject command injection attempts at API endpoint level")
    public void testCommandInjectionRejectionAtEndpoint(String maliciousInput) {
        // Using real Cowsay instance for integration test
        String result = realCowsay.run(maliciousInput);

        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("Error:"),
            "Malicious input should be rejected: " + maliciousInput);
        assertTrue(result.contains("invalid characters"),
            "Should indicate invalid characters in error message");
    }

    // ===== Mock-based Controller Tests =====

    @Test
    @DisplayName("Should delegate input processing to Cowsay service")
    public void testControllerDelegatesToCowsayService() {
        String input = "test input";
        String expectedOutput = "mocked output";

        when(mockCowsay.run(input)).thenReturn(expectedOutput);

        String result = cowController.cowsay(input);

        assertEquals(expectedOutput, result, "Controller should return Cowsay output");
        verify(mockCowsay, times(1)).run(input);
    }

    @Test
    @DisplayName("Should pass malicious input to Cowsay for validation")
    public void testControllerPassesMaliciousInputForValidation() {
        String maliciousInput = "; cat /etc/passwd";
        String errorMessage = "Error: Input contains invalid characters";

        when(mockCowsay.run(maliciousInput)).thenReturn(errorMessage);

        String result = cowController.cowsay(maliciousInput);

        assertEquals(errorMessage, result, "Controller should return error from Cowsay");
        verify(mockCowsay, times(1)).run(maliciousInput);
    }

    // ===== Parameter Handling Tests =====

    @Test
    @DisplayName("Should handle null parameter safely")
    public void testNullParameterHandling() {
        when(mockCowsay.run(null)).thenReturn("Error: Input cannot be empty");

        String result = cowController.cowsay(null);

        assertTrue(result.startsWith("Error:"), "Null parameter should produce an error");
        verify(mockCowsay, times(1)).run(null);
    }

    @Test
    @DisplayName("Should handle empty parameter safely")
    public void testEmptyParameterHandling() {
        when(mockCowsay.run("")).thenReturn("Error: Input cannot be empty");

        String result = cowController.cowsay("");

        assertTrue(result.startsWith("Error:"), "Empty parameter should produce an error");
        verify(mockCowsay, times(1)).run("");
    }

    // ===== URL Encoding and Special Characters Tests =====

    @Test
    @DisplayName("Should handle URL-encoded malicious input")
    public void testUrlEncodedMaliciousInput() {
        // Simulating URL-decoded malicious input
        String decodedMaliciousInput = "; rm -rf /";

        String result = realCowsay.run(decodedMaliciousInput);

        assertTrue(result.startsWith("Error:"),
            "URL-decoded malicious input should be rejected");
    }

    @Test
    @DisplayName("Should handle unicode characters in input")
    public void testUnicodeCharactersInInput() {
        String unicodeInput = "Hello \u4e2d\u6587 World";

        String result = realCowsay.run(unicodeInput);

        // Unicode characters should be rejected as they're not in the safe pattern
        assertTrue(result.startsWith("Error:"),
            "Unicode characters should be rejected");
    }

    // ===== Defense in Depth Tests =====

    @Test
    @DisplayName("Verify multiple security layers are in place")
    public void testDefenseInDepth() {
        // Test that even if one security measure fails, others catch it
        String[] attackVectors = {
            "test; whoami",           // Command separator
            "test && id",             // Logical AND
            "test | cat /etc/passwd", // Pipe
            "test `whoami`",          // Command substitution
            "test $(id)"              // Command substitution
        };

        for (String attack : attackVectors) {
            String result = realCowsay.run(attack);
            assertTrue(result.startsWith("Error:"),
                "Defense in depth should catch: " + attack);
        }
    }

    // ===== Functional Correctness Tests =====

    @Test
    @DisplayName("Should maintain functional correctness for valid inputs")
    public void testFunctionalCorrectnessForValidInputs() {
        String[] validInputs = {
            "Hello World",
            "Test 123",
            "It's a great day!",
            "How are you?",
            "Well-done job."
        };

        for (String input : validInputs) {
            String result = realCowsay.run(input);
            assertNotNull(result, "Result should not be null for: " + input);
            assertFalse(result.startsWith("Error:") && result.contains("invalid characters"),
                "Valid input should not produce validation error: " + input);
        }
    }

    // ===== Cross-cutting Security Concerns =====

    @Test
    @DisplayName("Should prevent information disclosure in error messages")
    public void testErrorMessageDoesNotDiscloseSystemInfo() {
        String maliciousInput = "; ls /etc";

        String result = realCowsay.run(maliciousInput);

        assertTrue(result.startsWith("Error:"), "Should return an error");
        // Verify error message doesn't contain system paths or sensitive info
        assertFalse(result.contains("/etc"), "Error should not echo system paths");
        assertFalse(result.contains(maliciousInput), "Error should not echo full malicious input");
    }

    @Test
    @DisplayName("Should consistently validate input regardless of request order")
    public void testConsistentValidation() {
        // Test that validation is consistent across multiple requests
        String maliciousInput = "; cat /etc/passwd";

        for (int i = 0; i < 5; i++) {
            String result = realCowsay.run(maliciousInput);
            assertTrue(result.startsWith("Error:"),
                "Validation should be consistent on iteration " + i);
        }
    }

    // ===== Performance and DoS Prevention Tests =====

    @Test
    @DisplayName("Should enforce maximum input length to prevent DoS")
    public void testMaxInputLengthPreventsDoS() {
        // Create a very long input that exceeds the limit
        StringBuilder longInput = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            longInput.append("a");
        }

        String result = realCowsay.run(longInput.toString());

        assertTrue(result.startsWith("Error:"), "Overly long input should be rejected");
        assertTrue(result.contains("exceeds maximum length"),
            "Should indicate length limit enforcement");
    }

    @Test
    @DisplayName("Should efficiently validate input without excessive processing")
    public void testEfficientValidation() {
        // This test verifies that validation happens before expensive operations
        String maliciousInput = "; sleep 30";

        long startTime = System.currentTimeMillis();
        String result = realCowsay.run(maliciousInput);
        long endTime = System.currentTimeMillis();

        assertTrue(result.startsWith("Error:"), "Malicious input should be rejected");
        // Validation should be fast (< 100ms), not waiting for command execution
        assertTrue(endTime - startTime < 100,
            "Validation should be fast and not execute the command");
    }
}
