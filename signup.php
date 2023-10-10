<?php
$db = mysqli_connect('localhost', 'root', '', 'bugallondashboard');
if (!$db) {
    echo json_encode(array("status" => "Error", "message" => "Database Connection Failed"));
    exit; // Terminate the script
}

$username = $_POST["username"];
$email = $_POST["email"];
$contact = $_POST["contact"];
$birthdate = $_POST["birthdate"];
$password = $_POST["password"];
$confirmpassword = $_POST["confirmpassword"];


// Validate email
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(array("status" => "Error", "message" => "Invalid email format"));
    exit;
}

// Validate required fields
if (empty($username) || empty($email) || empty($contact) || empty($birthdate) || empty($password) || empty($confirmpassword)) {
    echo json_encode(array("status" => "Error", "message" => "All fields are required"));
    exit;
}

// Check if passwords match
if ($password !== $confirmpassword) {
    echo json_encode(array("status" => "Error", "message" => "Passwords do not match"));
    exit;
}

$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

$stmt = $db->prepare("SELECT * FROM user WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 1) {
    echo json_encode(array("status" => "Error", "message" => "User Already Exists"));
} else {
  
    $stmt = $db->prepare("INSERT INTO user (username, email, contact, birthdate, password) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $username, $email, $contact, $birthdate, $hashedPassword);
    
    if ($stmt->execute()) {
        echo json_encode(array("status" => "Success", "message" => "Registration Success"));
        header('Location: index.html');
    } else {
        echo json_encode(array("status" => "Error", "message" => "Registration Failed"));
    }
}

mysqli_close($db);
?>
