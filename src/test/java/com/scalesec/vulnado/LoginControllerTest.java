package com.scalesec.vulnado;

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
 * Integration tests for LoginController to ensure SQL injection prevention
 * works correctly through the entire authentication flow.
 */
@DisplayName("LoginController SQL Injection Prevention Tests")
class LoginControllerTest {

    private LoginController loginController;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @BeforeEach
    void setUp() throws SQLException {
        loginController = new LoginController();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
    }

    @Test
    @DisplayName("Should reject SQL injection attempt in login endpoint")
    void testLoginRejectsSqlInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin' OR '1'='1";
        request.password = "anything";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success, "Login should fail for SQL injection attempt");
            assertEquals("Invalid username or password", response.message);
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should handle UNION-based SQL injection in login")
    void testLoginRejectsUnionBasedInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin' UNION SELECT 'admin','known_hash' --";
        request.password = "password";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should handle DROP TABLE injection in login")
    void testLoginRejectsDropTableInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin'; DROP TABLE users; --";
        request.password = "password";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            assertEquals("Invalid username or password", response.message);
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should successfully authenticate valid user")
    void testLoginSuccessWithValidCredentials() throws SQLException {
        // Arrange
        String validUsername = "john_doe";
        String plainPassword = "securePassword123";
        // BCrypt hash of "securePassword123"
        String hashedPassword = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = validUsername;
        request.password = plainPassword;

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class);
             MockedStatic<PasswordUtil> mockedPasswordUtil = mockStatic(PasswordUtil.class)) {

            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("username")).thenReturn(validUsername);
            when(mockResultSet.getString("password")).thenReturn(hashedPassword);

            // Mock password verification
            mockedPasswordUtil.when(() -> PasswordUtil.verify(plainPassword, hashedPassword))
                .thenReturn(true);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertTrue(response.success, "Login should succeed with valid credentials");
            assertEquals("Login successful", response.message);
            verify(mockPreparedStatement).setString(1, validUsername);
        }
    }

    @Test
    @DisplayName("Should reject valid username with wrong password")
    void testLoginFailsWithWrongPassword() throws SQLException {
        // Arrange
        String validUsername = "john_doe";
        String wrongPassword = "wrongPassword";
        String hashedPassword = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = validUsername;
        request.password = wrongPassword;

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class);
             MockedStatic<PasswordUtil> mockedPasswordUtil = mockStatic(PasswordUtil.class)) {

            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("username")).thenReturn(validUsername);
            when(mockResultSet.getString("password")).thenReturn(hashedPassword);

            mockedPasswordUtil.when(() -> PasswordUtil.verify(wrongPassword, hashedPassword))
                .thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success, "Login should fail with wrong password");
            assertEquals("Invalid username or password", response.message);
        }
    }

    @Test
    @DisplayName("Should reject non-existent username")
    void testLoginFailsWithNonExistentUser() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "nonexistent_user";
        request.password = "anypassword";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            assertEquals("Invalid username or password", response.message);
        }
    }

    @Test
    @DisplayName("Should handle comment-based SQL injection in login")
    void testLoginRejectsCommentBasedInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin'--";
        request.password = "";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should handle stacked queries injection in login")
    void testLoginRejectsStackedQueriesInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin'; INSERT INTO users VALUES ('hacker', 'pass'); --";
        request.password = "password";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should handle time-based blind SQL injection in login")
    void testLoginRejectsTimeBasedBlindInjection() throws SQLException {
        // Arrange
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "admin' OR SLEEP(5) --";
        request.password = "password";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            // Verify the malicious payload is treated as a literal string parameter
            verify(mockPreparedStatement).setString(1, request.username);
        }
    }

    @Test
    @DisplayName("Should handle usernames with legitimate special characters")
    void testLoginWithSpecialCharactersInUsername() throws SQLException {
        // Arrange - some systems allow email addresses as usernames
        LoginController.LoginRequest request = new LoginController.LoginRequest();
        request.username = "user@example.com";
        request.password = "password";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockResultSet.next()).thenReturn(false);

            // Act
            LoginController.LoginResponse response = loginController.login(request);

            // Assert
            assertFalse(response.success);
            // Verify special character is handled correctly as part of username
            verify(mockPreparedStatement).setString(1, "user@example.com");
        }
    }
}
