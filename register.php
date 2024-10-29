<?php
// Change this to your connection info.
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'phplogin';
// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

// Now we check if the data was submitted.
if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
    exit('Please complete the registration form!');
}

// Make sure the submitted registration values are not empty.
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
    exit('Please complete the registration form');
}

// Validate email, username, and password length
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    exit('Email is not valid!');
}
if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
    exit('Username is not valid!');
}
if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
    exit('Password must be between 5 and 20 characters long!');
}

// Check if the account with that username exists
if ($stmt = $con->prepare('SELECT id FROM accounts WHERE username = ?')) {
    $stmt->bind_param('s', $_POST['username']);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo 'Username exists, please choose another!';
        $stmt->close();
    } else {
        // Insert new account without password hashing
        $stmt->close();
        if ($stmt = $con->prepare('INSERT INTO accounts (username, password, email, activation_code) VALUES (?, ?, ?, ?)')) {
            $password = $_POST['password']; // Store plain password (not recommended)
            $activation_code = uniqid();
            $stmt->bind_param('ssss', $_POST['username'], $password, $_POST['email'], $activation_code);
            $stmt->execute();
            $stmt->close();

            // Send activation email
            $from = 'noreply@yourdomain.com';
            $subject = 'Account Activation Required';
            $headers = 'From: ' . $from . "\r\n" .
                'Reply-To: ' . $from . "\r\n" .
                'X-Mailer: PHP/' . phpversion() . "\r\n" .
                'MIME-Version: 1.0' . "\r\n" .
                'Content-Type: text/html; charset=UTF-8' . "\r\n";
            $activate_link = 'http://yourdomain.com/phplogin/activate.php?email=' . $_POST['email'] . '&code=' . $activation_code;
            $message = '<p>Please click the following link to activate your account: <a href="' . $activate_link . '">' . $activate_link . '</a></p>';
            mail($_POST['email'], $subject, $message, $headers);
            echo 'Please check your email to activate your account!';
        } else {
            echo 'Could not prepare statement!';
        }
    }
} else {
    echo 'Could not prepare statement!';
}

$con->close();
