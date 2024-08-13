import sys
import requests
import base64
import os
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox)
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt
import json

# Set up your VirusTotal API key
API_KEY = 'YPUR-API-KEY'

# VirusTotal API endpoints
IP_ENDPOINT = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
URL_ENDPOINT = 'https://www.virustotal.com/api/v3/urls/{}'
FILE_REPORT_ENDPOINT = 'https://www.virustotal.com/api/v3/files/{}'
FILE_UPLOAD_ENDPOINT = 'https://www.virustotal.com/api/v3/files'
ANALYSIS_REPORT_ENDPOINT = 'https://www.virustotal.com/api/v3/analyses/{}'

class VirusTotalGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.output_format = 'readable'  # Default output format
    
    def initUI(self):
        # Set up the GUI layout
        self.setWindowTitle('VirusTotal Client')
        self.setGeometry(300, 300, 800, 600)
        
        # Set background color to blue
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor('#1a73e8'))
        self.setPalette(palette)
        
        layout = QVBoxLayout()
        
        # IP Address section
        ip_layout = QHBoxLayout()
        ip_label = QLabel('IP Address:')
        self.ip_input = QLineEdit()
        ip_button = QPushButton('Check IP')
        ip_button.clicked.connect(self.check_ip)
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        ip_layout.addWidget(ip_button)
        
        # URL section
        url_layout = QHBoxLayout()
        url_label = QLabel('URL:')
        self.url_input = QLineEdit()
        url_button = QPushButton('Check URL')
        url_button.clicked.connect(self.check_url)
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(url_button)
        
        # File Hash section
        file_hash_layout = QHBoxLayout()
        file_hash_label = QLabel('File Hash:')
        self.file_hash_input = QLineEdit()
        file_hash_button = QPushButton('Check File Hash')
        file_hash_button.clicked.connect(self.check_file_hash)
        file_hash_layout.addWidget(file_hash_label)
        file_hash_layout.addWidget(self.file_hash_input)
        file_hash_layout.addWidget(file_hash_button)
        
        # File Upload section
        file_upload_layout = QHBoxLayout()
        file_upload_button = QPushButton('Upload File')
        file_upload_button.setFixedSize(150, 40)
        file_upload_button.clicked.connect(self.upload_file)
        file_upload_layout.addWidget(file_upload_button)
        
        # Format toggle button
        format_layout = QHBoxLayout()
        self.format_button = QPushButton('Switch to JSON Format')
        self.format_button.setFixedSize(160,30)
        self.format_button.clicked.connect(self.toggle_format)
        format_layout.addWidget(self.format_button)
        
        # Text Area for output
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        
        # Adding all widgets to the main layout
        layout.addLayout(ip_layout)
        layout.addLayout(url_layout)
        layout.addLayout(file_hash_layout)
        layout.addLayout(file_upload_layout)
        layout.addLayout(format_layout)
        layout.addWidget(self.result_area)
        
        self.setLayout(layout)
    
    def check_ip(self):
        ip = self.ip_input.text().strip()
        if ip:
            ip_info = get_ip_info(ip)
            self.display_results(ip_info)
        else:
            self.show_error("Please enter a valid IP address.")
    
    def check_url(self):
        url = self.url_input.text().strip()
        if url:
            url_info = get_url_info(url)
            self.display_results(url_info)
        else:
            self.show_error("Please enter a valid URL.")
    
    def check_file_hash(self):
        file_hash = self.file_hash_input.text().strip()
        if file_hash:
            file_info = get_file_info(file_hash)
            self.display_results(file_info)
        else:
            self.show_error("Please enter a valid file hash.")
    
    def upload_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload", "", "All Files (*);;Executable Files (*.exe)", options=options)
        if file_path:
            upload_response = upload_file(file_path)
            if 'error' in upload_response:
                self.show_error(upload_response['error'])
            else:
                self.result_area.append("File uploaded successfully.")
                scan_id = upload_response['data']['id']
                self.result_area.append(f"Scan ID: {scan_id}")
                analysis_results = get_analysis_results(scan_id)
                self.display_results(analysis_results)
        else:
            self.show_error("No file selected.")
    
    def display_results(self, data):
        self.result_area.clear()
        if 'error' in data:
            self.result_area.append(data['error'])
        else:
            formatted_result = self.format_data(data)
            self.result_area.append(formatted_result)
    
    def format_data(self, data):
        if self.output_format == 'readable':
            return self.format_as_readable(data)
        else:
            return json.dumps(data, indent=4)
    
    def format_as_readable(self, data):
        # Example of basic readable formatting; adjust as needed
        if 'data' in data:
            data = data['data']
            if 'attributes' in data:
                data = data['attributes']
        readable_result = ""
        for key, value in data.items():
            readable_result += f"{key}: {value}\n"
        return readable_result
    
    def toggle_format(self):
        if self.output_format == 'readable':
            self.output_format = 'json'
            self.format_button.setText('Switch to Readable Format')
        else:
            self.output_format = 'readable'
            self.format_button.setText('Switch to JSON Format')
    
    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

def get_ip_info(ip):
    headers = {'x-apikey': API_KEY}
    response = requests.get(IP_ENDPOINT.format(ip), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to get information for IP: {ip}. Status code: {response.status_code}"}

def get_url_info(url):
    headers = {'x-apikey': API_KEY}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(URL_ENDPOINT.format(encoded_url), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to get information for URL: {url}. Status code: {response.status_code}"}

def get_file_info(filehash):
    headers = {'x-apikey': API_KEY}
    response = requests.get(FILE_REPORT_ENDPOINT.format(filehash), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to get information for file hash: {filehash}. Status code: {response.status_code}"}

def upload_file(file_path):
    headers = {'x-apikey': API_KEY}
    if os.path.exists(file_path):
        files = {'file': open(file_path, 'rb')}
        response = requests.post(FILE_UPLOAD_ENDPOINT, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to upload file. Status code: {response.status_code}"}
    else:
        return {"error": "Invalid file path."}

def get_analysis_results(scan_id):
    headers = {'x-apikey': API_KEY}
    response = requests.get(ANALYSIS_REPORT_ENDPOINT.format(scan_id), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to get analysis report. Status code: {response.status_code}"}

def main():
    app = QApplication(sys.argv)
    gui = VirusTotalGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
