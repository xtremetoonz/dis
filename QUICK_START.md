# Domain Security Scanner Quick Start

## Setup
1. Create virtual environment:
```python -m venv venv```
2. Activate virtual environment:
   - Windows: ```.\venv\Scripts\activate```
   - Unix/MacOS: ```source venv/bin/activate```
3. Install requirements:
```pip install -r requirements.txt```

## Usage
Basic scan:
```python -m scanner.cli example.com```

With Cert Spotter API:
```python -m scanner.cli example.com --cert-spotter-key YOUR_KEY```

Output to file:
```python -m scanner.cli example.com -o results.json --json```
