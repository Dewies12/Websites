<?php
require 'config.php';
	$username ="";
	$email = "";
	$errors = array();
	if (isset($_POST['login_user'])) {
		$username = mysqli_real_escape_string($db, $_POST['username']);
		$password = mysqli_real_escape_string($db, $_POST['password']);
	  
		if (empty($username)) {
			array_push($errors, "Username is required");
		}
		if (empty($password)) {
			array_push($errors, "Password is required");
		}
	  
		if (count($errors) == 0) {
			$password = sha1($password);
			$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
			$results = mysqli_query($db, $query);
			if (mysqli_num_rows($results) == 1) {
			  $_SESSION['username'] = $username;
			  header('location: ../store.html');
			}else {
				array_push($errors, "Wrong username/password combination");
				
			}

		}
		echo sha1($password);
		echo "SELECT * FROM users WHERE username='$username' AND password='$password'";
		echo $password;
	  }
	  
// Initialize the session
		
?>