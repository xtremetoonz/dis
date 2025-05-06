<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Scanner</title>
</head>
<body>
    <h1>Domain Scanner</h1>
    <form action="results.php" method="POST">
        <label for="domain">Enter Domain:</label>
        <input type="text" id="domain" name="domain" required>
        <button type="submit">Scan</button>
    </form>
    <div id="results"></div>

    <script>
    document.querySelector('form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        document.getElementById('results').innerHTML = 'Scanning...';
        
        const formData = new FormData(this);
        
        fetch('results.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            document.getElementById('results').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(error => {
            document.getElementById('results').innerHTML = 'Error: ' + error.message;
        });
    });
    </script>
</body>
</html>
