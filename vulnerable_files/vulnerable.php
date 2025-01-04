// PHP (Cross-Site Request Forgery - CSRF)
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $newEmail = $_POST['email'];
    // No CSRF token verification
    $userId = $_SESSION['user_id'];
    // Update email in database
    // ...
    echo "Email updated to: " . htmlspecialchars($newEmail);
}
?>
<form method="POST">
    <label for="email">New Email:</label>
    <input type="email" id="email" name="email">
    <button type="submit">Update Email</button>
</form>

