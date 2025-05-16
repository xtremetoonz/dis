<?php
// Database connection
$servername = "localhost";
$username = "dis_user";
$password = "your_password";
$dbname = "dis_database";

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch scan history
$sql = "SELECT id, domain, created_at FROM scans ORDER BY created_at DESC";
$result = $conn->query($sql);

echo "<h1>Scan History</h1>";
if ($result->num_rows > 0) {
    echo "<table border='1'>";
    echo "<tr><th>Scan ID</th><th>Domain</th><th>Date</th></tr>";
    while($row = $result->fetch_assoc()) {
        echo "<tr><td>" . $row["id"] . "</td><td>" . $row["domain"] . "</td><td>" . $row["created_at"] . "</td></tr>";
    }
    echo "</table>";
} else {
    echo "<p>No scan history available.</p>";
}

$conn->close();
?>
