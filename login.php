<?php
session_start();

// Establish a database connection
$db = mysqli_connect('localhost', 'root', '', 'bugallondashboard');
if (!$db) {
    echo json_encode(array("status" => "Error", "message" => "Database Connection Failed"));
    exit;
}

// Function to authenticate the user
function authenticateUser($username, $password) {
    global $db;
    
    // Use prepared statement to retrieve user data
    $stmt = $db->prepare("SELECT * FROM user WHERE email = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row["password"])) {
            return true;
        }
    }
    
    return false;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["email"];
    $password = $_POST["password"];
    $remember = isset($_POST["remember"]) ? true : false;

    $authenticated = authenticateUser($username, $password);

    if ($authenticated) {
        // Set a session variable for authentication
        $_SESSION["email"] = $username;

        // Set a cookie if "Remember Me" is checked
        if ($remember) {
            $cookieValue = base64_encode($username . ":" . $password);
            setcookie("rememberMe", $cookieValue, time() + (86400 * 30), "/"); // Cookie expires in 30 days
        }

        header('Location: home.html');
        exit;
    } else {
        echo json_encode(array("status" => "Error", "message" => "Incorrect Email or Password"));
    }
}

mysqli_close($db);
?>
