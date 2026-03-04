package com.scalesec.vulnado;

import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private String hashedPassword;

    public User() {
    }

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public static User fetch(String un) {
        // FIXED: Using PreparedStatement with parameterized query to prevent SQL injection
        String query = "SELECT * FROM users WHERE username = ?";

        try (Connection connection = Postgres.connection();
             PreparedStatement pstmt = connection.prepareStatement(query)) {

            // Set the parameter safely - JDBC will handle proper escaping
            pstmt.setString(1, un);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    User user = new User();
                    user.setUsername(rs.getString("username"));
                    user.hashedPassword = rs.getString("password");
                    return user;
                }
            }
        } catch (SQLException e) {
            System.err.println("SQL error: " + e.getMessage());
        }
        return null;
    }

    public boolean verifyPassword(String password) {
        if (hashedPassword == null) {
            return false;
        }
        return PasswordUtil.verify(password, hashedPassword);
    }
}
