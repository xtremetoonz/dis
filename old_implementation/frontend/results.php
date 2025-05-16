<?php
header('Content-Type: application/json');

try {
    // Debug logging
    error_log("POST data: " . print_r($_POST, true));
    
    // Get domain from POST data
    if (!isset($_POST['domain']) || empty($_POST['domain'])) {
        throw new Exception('Domain is required');
    }

    $domain = $_POST['domain'];
    error_log("Processing domain: " . $domain);

    // Prepare API request using port 5000
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'http://localhost:5000/api/scan',  // Using port 5000 instead of Unix socket
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['domain' => $domain]),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json']
    ]);

    // Execute API request
    $response = curl_exec($ch);
    
    if ($response === false) {
        error_log("Curl error: " . curl_error($ch));
        throw new Exception('Curl error: ' . curl_error($ch));
    }
    
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    error_log("API response code: " . $httpCode);
    error_log("API response: " . $response);

    if ($httpCode !== 200) {
        throw new Exception('API request failed with status code: ' . $httpCode);
    }

    // Decode API response
    $result = json_decode($response, true);
    if ($result === null) {
        throw new Exception('Failed to decode API response: ' . json_last_error_msg());
    }

    // Send response back to client
    echo json_encode($result);

} catch (Exception $e) {
    error_log("Error in results.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => $e->getMessage(),
        'timestamp' => '2025-05-02 22:26:47'
    ]);
}
?>
