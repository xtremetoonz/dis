<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $domain = $_POST['domain'];

    // Flask API URL
    $api_url = "http://localhost:5000/api/scan";

    // Prepare cURL request
    $ch = curl_init($api_url);
    $payload = json_encode(array("domain" => $domain));
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // Execute cURL and get the response
    $response = curl_exec($ch);
    curl_close($ch);

    // Decode JSON response
    $result = json_decode($response, true);

    // Display the results
    echo "<h1>Scan Results for: $domain</h1>";
    if (isset($result["results"])) {
        echo "<pre>" . json_encode($result["results"], JSON_PRETTY_PRINT) . "</pre>";
    } else {
        echo "<p>Error: " . $result["error"] . "</p>";
    }
}
?>
