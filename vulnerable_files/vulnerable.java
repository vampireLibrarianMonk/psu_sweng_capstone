// Java (SQL Injection)
import java.sql.*;

public class Vulnerable {
    public void getUserData(String username) {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("User ID: " + rs.getInt("id"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}
