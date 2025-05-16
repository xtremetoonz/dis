CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    scan_date DATETIME NOT NULL,
    user VARCHAR(255) NOT NULL,
    results TEXT NOT NULL,
    warnings TEXT,
    INDEX (domain),
    INDEX (user),
    INDEX (scan_date)
);
