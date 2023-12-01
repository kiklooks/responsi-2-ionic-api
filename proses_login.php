<?php

// Include your database connection file or establish a connection here
// For example: include('db_connection.php');

// Assuming you have a users table with fields: id, username, password
// Replace these with your actual table and field names

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get data from Angular POST request
    $data = json_decode(file_get_contents("php://input"));

    // Sanitize and validate input data
    $username = filter_var($data->username, FILTER_SANITIZE_STRING);
    $password = filter_var($data->password, FILTER_SANITIZE_STRING);

    // You may want to hash the password before comparing it to the database
    // $hashedPassword = hash('sha256', $password);

    // Replace the following with your database query to check the username and password
    // Example assumes you have a function checkLogin in your database connection file
    // $loggedInUser = checkLogin($username, $hashedPassword);

    // Replace the following with your actual database connection and query logic
    $host = "your_database_host";
    $db = "your_database_name";
    $user = "your_database_user";
    $pass = "your_database_password";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Query to check if the username and password match
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password); // Use $hashedPassword if you hashed the password

        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Authentication successful
            $response = array('status_login' => 'berhasil', 'token' => 'your_generated_token', 'username' => $username);
        } else {
            // Authentication failed
            $response = array('status_login' => 'gagal');
        }

        echo json_encode(array('data' => $response));

    } catch (PDOException $e) {
        // Handle database connection errors
        echo json_encode(array('error' => 'Database connection error: ' . $e->getMessage()));
    }
} else {
    // Handle invalid request method
    echo json_encode(array('error' => 'Invalid request method'));
}

?>
