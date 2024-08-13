# VirusTotal Client

## Overview

The VirusTotal Client is a desktop application built with PyQt5 for interacting with the VirusTotal API. It allows users to check IP addresses, URLs, and file hashes for security information, as well as upload files for analysis.

## Features

- **Check IP Address**: Retrieve security information about a specified IP address.
- **Check URL**: Retrieve security information about a specified URL.
- **Check File Hash**: Retrieve security information about a specified file hash.
- **Upload File**: Upload a file for analysis and retrieve the scan results.
- **Toggle Output Format**: Switch between a readable format and JSON format for displaying results.

## Requirements

- Python 3.x
- PyQt5
- Requests

## Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/Raulisr00t/VirustotalClient.git
    ```

2. **Install Dependencies**:

    ```bash
    pip install PyQt5 requests
    ```

## Usage

1. **Run the Application**:

    ```bash
    python app.py
    ```

2. **Use the Application**:
   - **Check IP Address**: Enter an IP address and click "Check IP".
   - **Check URL**: Enter a URL and click "Check URL".
   - **Check File Hash**: Enter a file hash and click "Check File Hash".
   - **Upload File**: Click "Upload File" and select a file to upload for analysis.
   - **Toggle Output Format**: Click the button to switch between readable format and JSON format for results.

## Configuration

- **API Key**: Replace the `API_KEY` variable in `app.py` with your VirusTotal API key.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [VirusTotal API Documentation](https://www.virustotal.com/gui/docs)
- [PyQt5 Documentation](https://www.riverbankcomputing.com/software/pyqt/intro)
