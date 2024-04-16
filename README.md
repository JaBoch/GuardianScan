GuardianScan is a graphical user interface (GUI) application built using Python and PyQt5. It provides an intuitive interface for running network scans using the Nmap tool.
Features

    Scan target hosts for open ports and services.
    Customize scan options including OS detection and service version detection.
    Run scans with or without root privileges.
    Export scan results to CSV format.

Installation

Clone the repository:

    git clone https://github.com/your-username/GuardianScan.git

Navigate to the project directory:

    cd GuardianScan

Install the required dependencies:

    pip install -r requirements.txt

Run the application:

    sudo python3 GuardianScan.py
Or:
    sudo ./GuardianScan

Usage

    Enter the target host IP address or hostname in the designated field.
    Optionally, specify additional scan options.
    Check the desired advanced options such as OS detection and service version detection.
    Check the "Run as root" option if required.
    Click the "Scan" button to start the scan.
    View the scan results in the output area.
    Export scan results if needed.
