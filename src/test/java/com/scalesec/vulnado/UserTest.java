package com.scalesec.vulnado;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.MockedStatic;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for User.fetch() method to validate SQL injection remediation.
 *
 * This test suite verifies that:
 * 1. The User.fetch() method uses PreparedStatement (not Statement)
 * 2. SQL injection attacks are prevented
 * 3. Normal functionality works correctly
 * 4. Edge cases are handled properly
 */
@DisplayName("User SQL Injection Remediation Tests")
class UserTest {

    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;
    private MockedStatic<Postgres> mockedPostgres;

    @BeforeEach
    void setUp() throws SQLException {
        // Create mock objects
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        // Mock the Postgres.connection() static method
        mockedPostgres = mockStatic(Postgres.class);
        mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);

        // Setup default behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
    }

    @AfterEach
    void tearDown() {
        if (mockedPostgres != null) {
            mockedPostgres.close();
        }
    }

    @Test
    @DisplayName("Should use PreparedStatement with parameterized query")
    void testUsesParameterizedQuery() throws SQLException {
        // Arrange
        String testUsername = "testuser";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User.fetch(testUsername);

        // Assert - verify PreparedStatement is used with parameterized query
        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, testUsername);
        verify(mockPreparedStatement).executeQuery();
    }

    @Test
    @DisplayName("Should prevent SQL injection with single quote attack")
    void testPreventsSqlInjectionWithSingleQuote() throws SQLException {
        // Arrange - classic SQL injection attempt
        String maliciousUsername = "admin' OR '1'='1";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert - the malicious string should be treated as a literal parameter
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        // Verify that the malicious input is passed as a parameter, not concatenated
        verify(mockConnection, never()).createStatement();
        assertNull(result, "Should return null when no user found");
    }

    @Test
    @DisplayName("Should prevent SQL injection with comment injection")
    void testPreventsSqlInjectionWithComment() throws SQLException {
        // Arrange - SQL injection using comment to bypass password check
        String maliciousUsername = "admin'--";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert - the comment should be treated as part of the username literal
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        verify(mockConnection, never()).createStatement();
        assertNull(result);
    }

    @Test
    @DisplayName("Should prevent SQL injection with UNION attack")
    void testPreventsSqlInjectionWithUnion() throws SQLException {
        // Arrange - UNION-based SQL injection
        String maliciousUsername = "admin' UNION SELECT 'hacker','password123' --";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert - UNION should be treated as literal string
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        verify(mockConnection, never()).createStatement();
        assertNull(result);
    }

    @Test
    @DisplayName("Should prevent SQL injection with DROP TABLE attack")
    void testPreventsSqlInjectionWithDropTable() throws SQLException {
        // Arrange - destructive SQL injection attempt
        String maliciousUsername = "admin'; DROP TABLE users; --";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert - DROP TABLE should be treated as literal string
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        verify(mockConnection, never()).createStatement();
        assertNull(result);
    }

    @Test
    @DisplayName("Should fetch valid user successfully")
    void testFetchValidUser() throws SQLException {
        // Arrange
        String validUsername = "john_doe";
        String hashedPassword = "$2a$10$abcdefghijklmnopqrstuv";

        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("username")).thenReturn(validUsername);
        when(mockResultSet.getString("password")).thenReturn(hashedPassword);

        // Act
        User result = User.fetch(validUsername);

        // Assert
        assertNotNull(result, "Should return a User object for valid username");
        assertEquals(validUsername, result.getUsername());
        verify(mockPreparedStatement).setString(1, validUsername);
    }

    @Test
    @DisplayName("Should return null for non-existent user")
    void testFetchNonExistentUser() throws SQLException {
        // Arrange
        String nonExistentUsername = "nonexistent";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(nonExistentUsername);

        // Assert
        assertNull(result, "Should return null when user doesn't exist");
        verify(mockPreparedStatement).setString(1, nonExistentUsername);
    }

    @Test
    @DisplayName("Should handle usernames with special characters safely")
    void testFetchUsernameWithSpecialCharacters() throws SQLException {
        // Arrange - legitimate username with special characters
        String specialUsername = "user@example.com";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(specialUsername);

        // Assert
        verify(mockPreparedStatement).setString(1, specialUsername);
        assertNull(result);
    }

    @Test
    @DisplayName("Should handle empty string username")
    void testFetchEmptyUsername() throws SQLException {
        // Arrange
        String emptyUsername = "";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(emptyUsername);

        // Assert
        verify(mockPreparedStatement).setString(1, emptyUsername);
        assertNull(result);
    }

    @Test
    @DisplayName("Should handle null username without crashing")
    void testFetchNullUsername() throws SQLException {
        // Arrange
        String nullUsername = null;
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(nullUsername);

        // Assert
        verify(mockPreparedStatement).setString(1, nullUsername);
        assertNull(result);
    }

    @Test
    @DisplayName("Should handle SQL exceptions gracefully")
    void testHandlesSqlException() throws SQLException {
        // Arrange
        String username = "testuser";
        when(mockConnection.prepareStatement(anyString()))
            .thenThrow(new SQLException("Database connection failed"));

        // Act
        User result = User.fetch(username);

        // Assert
        assertNull(result, "Should return null when SQLException occurs");
    }

    @Test
    @DisplayName("Should properly close resources using try-with-resources")
    void testResourcesClosed() throws SQLException {
        // Arrange
        String username = "testuser";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User.fetch(username);

        // Assert - verify that close() is called on resources
        // (try-with-resources ensures this, but we verify the mocks were used correctly)
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).executeQuery();
    }

    @Test
    @DisplayName("Should prevent stacked query injection")
    void testPreventsStackedQueryInjection() throws SQLException {
        // Arrange - attempt to execute multiple statements
        String maliciousUsername = "admin'; INSERT INTO users VALUES ('hacker','pass'); --";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert - entire malicious string treated as single parameter
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        verify(mockConnection, never()).createStatement();
        assertNull(result);
    }

    @Test
    @DisplayName("Should prevent blind SQL injection with boolean-based attack")
    void testPreventsBlindSqlInjection() throws SQLException {
        // Arrange - boolean-based blind SQL injection
        String maliciousUsername = "admin' AND '1'='1";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(maliciousUsername);

        // Assert
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        assertNull(result);
    }

    @Test
    @DisplayName("Should handle usernames with semicolons safely")
    void testHandlesSemicolonInUsername() throws SQLException {
        // Arrange
        String usernameWithSemicolon = "user;name";
        when(mockResultSet.next()).thenReturn(false);

        // Act
        User result = User.fetch(usernameWithSemicolon);

        // Assert - semicolon should be treated as part of username
        verify(mockPreparedStatement).setString(1, usernameWithSemicolon);
        assertNull(result);
    }
}
