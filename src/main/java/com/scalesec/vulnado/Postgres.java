package com.scalesec.vulnado;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Postgres {
    private static String url = System.getenv("JDBC_DATABASE_URL");
    private static String username = System.getenv("JDBC_DATABASE_USERNAME");
    private static String password = System.getenv("JDBC_DATABASE_PASSWORD");

    public static Connection connection() throws SQLException {
        if (url == null || url.isEmpty()) {
            url = "jdbc:postgresql://localhost:5432/vulnado";
        }
        if (username == null || username.isEmpty()) {
            username = "vulnado";
        }
        if (password == null || password.isEmpty()) {
            password = "vulnado";
        }

        return DriverManager.getConnection(url, username, password);
    }
}
