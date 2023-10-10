<?php
$db = mysqli_connect('localhost', 'root', '', 'bugallondashboard');
if (!$db) {
    echo json_encode(array("status" => "Error", "message" => "Database Connection Failed"));
    exit; // Terminate the script
}

$username = $_POST["adminusername"];
$email = $_POST["adminemail"];
$contact = $_POST["admincontact"];
$birthdate = $_POST["adminbirthdate"];
$password = $_POST["adminpassword"];
$confirmpassword = $_POST["adminconfirmpassword"];


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

$stmt = $db->prepare("SELECT * FROM admin WHERE adminusername = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 1) {
    echo json_encode(array("status" => "Error", "message" => "User Already Exists"));
} else {
  
    $stmt = $db->prepare("INSERT INTO admin (adminusername, adminemail, admincontact, adminbirthdate, adminpassword) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $username, $email, $contact, $birthdate, $hashedPassword);
    
    if ($stmt->execute()) {
        echo json_encode(array("status" => "Success", "message" => "Registration Success"));
        header('Location: loginAdmin.html');
    } else {
        echo json_encode(array("status" => "Error", "message" => "Registration Failed"));
    }
}

mysqli_close($db);
?>
