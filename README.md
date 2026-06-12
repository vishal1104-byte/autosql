# 🔍 AutoSQL

**Automated SQL Injection Vulnerability Scanner with Multi-Threading Support**

## About

#AutoSQL is a powerful, automated SQL injection scanner that leverages SQLMap with multi-threading capabilities. It's designed for security professionals and penetration testers to efficiently test multiple targets for SQL injection vulnerabilities.

## Features

-  Multi-threaded scanning for faster results
-  Batch URL processing from file
-  Automatic SQLMap setup and configuration
-  Customizable risk and level settings
-  Detailed logging and output management

## Quick Installation

# Clone the repository
git clone https://github.com/YOUR_USERNAME/autosql.git
cd autosql

# Make executable
chmod +x autosql

# Move to system PATH
sudo cp autosql /usr/local/bin/

# Run AutoSQL
autosql --help

## Basis Command

# Display help
./autosql --help

# Scan single URL
./autosql -url "http://example.com/page.php?id=1"

# Scan with specific parameters
./autosql -url "http://example.com/page.php?id=1" -risk 3 -level 5

# Enable verbose output
./autosql -url "http://example.com/page.php?id=1" -verbose

# Scan from file (batch processing)
./autosql -file targets.txt

# Batch scan with 20 concurrent threads
./autosql -file targets.txt -threads 20

## Troubleshooting

SQLMap Not Found

# AutoSQL will attempt to download automatically
# Manual download:
git clone https://github.com/sqlmapproject/sqlmap.git
sudo mv sqlmap /opt/

Permission Denied
chmod +x autosql
sudo cp autosql /usr/local/bin/

Python Version Issues
# Check Python version
python3 --version

# Install Python 3.7+ if needed
sudo apt install python3 python3-pip -y

Threading Problems
# Reduce thread count
./autosql -file targets.txt -threads 5
Legal Disclaimer
IMPORTANT: This tool is for educational purposes and authorized security testing ONLY.

DO: Test your own applications

DO: Test applications you have written permission to test

DON'T: Scan websites without authorization

DON'T: Use for illegal activities

Users are responsible for compliance with all applicable laws. The author assumes no liability for misuse.

##Acknowledgments

SQLMap Project - The amazing SQL injection engine
Kali Linux Community - Testing and feedback

##License
This project is licensed under the MIT License - see the LICENSE file for details.

##Author : Vishal Tiwari 
