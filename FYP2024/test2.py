import sys
import subprocess
import csv
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QLineEdit,
    QTextEdit, QListWidget, QAction, QFileDialog, QHBoxLayout, QCheckBox, QInputDialog, QDialog, QMessageBox,
    QSplitter
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import os

class NmapGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Guardian Scan")
        self.setGeometry(100, 100, 1000, 600)  # Increased width for the right section

        # Create input fields
        self.host_label = QLabel("Target Host:")
        self.host_label.setFont(QFont("Arial", 12))
        self.host_input = QLineEdit()
        self.host_input.setFont(QFont("Arial", 12))
        self.scan_options_label = QLabel("Scan Options:")
        self.scan_options_label.setFont(QFont("Arial", 12))
        self.scan_options_input = QLineEdit()
        self.scan_options_input.setFont(QFont("Arial", 12))

        # Advanced options
        self.advanced_options_label = QLabel("Advanced Options:")
        self.advanced_options_label.setFont(QFont("Arial", 12))
        self.os_detection_checkbox = QCheckBox("OS Detection")
        self.os_detection_checkbox.setFont(QFont("Arial", 12))
        self.service_version_checkbox = QCheckBox("Service Version Detection")
        self.service_version_checkbox.setFont(QFont("Arial", 12))

        # Run as root checkbox
        self.run_as_root_checkbox = QCheckBox("Run as root")
        self.run_as_root_checkbox.setFont(QFont("Arial", 12))

        # Create buttons
        self.scan_button = QPushButton("Scan")
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; border-radius: 5px; }"
                                       "QPushButton:hover { background-color: #45a049; }"
                                       "QPushButton:pressed { background-color: #4CAF50; }")
        self.scan_button.clicked.connect(self.start_scan)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setFont(QFont("Arial", 12))
        self.stop_button.setStyleSheet("QPushButton { background-color: #f44336; color: white; border-radius: 5px; }"
                                       "QPushButton:hover { background-color: #d32f2f; border: 2px solid #b71c1c; }"
                                       "QPushButton:pressed { background-color: #b71c1c; border: 2px solid #b71c1c; }")
        self.stop_button.setDisabled(True)
        self.stop_button.clicked.connect(self.stop_scan)

        # Clear fields button
        self.clear_button = QPushButton("Clear Fields")
        self.clear_button.setFont(QFont("Arial", 12))
        self.clear_button.setStyleSheet("QPushButton { background-color: #ff9800; color: white; border-radius: 5px; }"
                                        "QPushButton:hover { background-color: #f57c00; }"
                                        "QPushButton:pressed { background-color: #ff9800; }")
        self.clear_button.clicked.connect(self.clear_fields)

        # Add tooltips to UI elements
        self.scan_button.setToolTip("Start the scan")
        self.stop_button.setToolTip("Stop the scan")
        self.clear_button.setToolTip("Clear input fields")
        self.os_detection_checkbox.setToolTip("Enable OS Detection")
        self.service_version_checkbox.setToolTip("Enable Service Version Detection")
        self.run_as_root_checkbox.setToolTip("Run the scan with root privileges")

        self.logo_label = QLabel()
        pixmap = QPixmap("/home/jboch/Downloads/GuardianScan.png")  # Path to your image file
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignLeft | Qt.AlignBottom)  # Align bottom left
        self.logo_label.setScaledContents(True)  # Scale image to fit label


        # Layout for left section
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.host_label)
        left_layout.addWidget(self.host_input)
        left_layout.addWidget(self.scan_options_label)
        left_layout.addWidget(self.scan_options_input)
        left_layout.addWidget(self.advanced_options_label)
        left_layout.addWidget(self.os_detection_checkbox)
        left_layout.addWidget(self.service_version_checkbox)
        left_layout.addWidget(self.run_as_root_checkbox)
        left_layout.addWidget(self.scan_button)
        left_layout.addWidget(self.stop_button)
        left_layout.addWidget(self.clear_button)  # Add the clear button
        left_layout.addWidget(self.clear_button)
        left_layout.addWidget(self.logo_label)  # Add the logo label
        left_layout.addStretch(1)

        # Left widget
        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        # Create output area
        self.output_label = QLabel("Scan Results:")
        self.output_label.setFont(QFont("Arial", 12))
        self.output_area = QTextEdit()
        self.output_area.setFont(QFont("Arial", 10))
        self.output_area.setReadOnly(True)

        # Scan history
        self.scan_history_label = QLabel("Scan History:")
        self.scan_history_label.setFont(QFont("Arial", 12))
        self.scan_history_list = QListWidget()
        self.scan_history_list.setFont(QFont("Arial", 10))

        # Right layout
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.output_label)
        right_layout.addWidget(self.output_area)
        right_layout.addWidget(self.scan_history_label)
        right_layout.addWidget(self.scan_history_list)

        # Right widget
        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        # Splitter
        splitter = QSplitter()
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        # Set the central widget
        self.setCentralWidget(splitter)

        # Menu bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        # Export scan results action
        export_action = QAction("Export Scan Results", self)
        export_action.triggered.connect(self.export_scan_results)
        file_menu.addAction(export_action)

        # Save scan configuration action
        save_config_action = QAction("Save Scan Configuration", self)
        save_config_action.triggered.connect(self.save_scan_configuration)
        file_menu.addAction(save_config_action)

        # Load scan configuration action
        load_config_action = QAction("Load Scan Configuration", self)
        load_config_action.triggered.connect(self.load_scan_configuration)
        file_menu.addAction(load_config_action)

        # Help menu
        help_menu = menubar.addMenu("Help")
        nmap_commands_action = QAction("Nmap Commands", self)
        nmap_commands_action.triggered.connect(self.show_nmap_commands)
        help_menu.addAction(nmap_commands_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        self.edit_toggle_action = QAction("Toggle Dark Mode", self)
        self.edit_toggle_action.triggered.connect(self.toggle_theme)
        edit_menu.addAction(self.edit_toggle_action)

        # Process object to handle running Nmap
        self.nmap_process = None
        self.root_password = None  # Store the root password
        self.scan_history = []  # List to store scan history


    def show_nmap_commands(self):
        # Create a popup window to display Nmap commands and descriptions
        popup_window = QDialog(self)
        popup_window.setWindowTitle("Nmap Commands")
        popup_window.setGeometry(200, 200, 600, 400)

        # Add a QTextEdit widget to display Nmap commands and descriptions
        commands_textedit = QTextEdit(popup_window)
        commands_textedit.setGeometry(10, 10, 580, 380)
        commands_textedit.setFont(QFont("Arial", 10))
        commands_textedit.setReadOnly(True)

        # Populate the QTextEdit with Nmap commands and descriptions
        commands_text = """ Nmap Commands:

    -sS: TCP SYN scan
         This scan sends SYN packets to the target ports and analyzes the responses to determine if the ports are open.

    -O: Enable OS detection
        This option enables Nmap's OS detection feature, which attempts to determine the operating system running on the target host.

    -sV: Probe open ports to determine service/version info
         This scan sends probes to the open ports on the target host to gather information about the services running on those ports, including their version numbers.

    -sU: UDP scan
         This scan sends UDP packets to the target ports and analyzes the responses to determine if the ports are open.

    -p: Specify ports to scan
         Use this option to specify a range or list of ports to scan. For example, -p 1-1000 or -p 22,80,443.

    -A: Aggressive scan options
         This option enables aggressive scan options, including OS detection, version detection, script scanning, and traceroute.

    --script: Run Nmap scripts
         Use this option to specify and run Nmap scripts. For example, --script vuln to run vulnerability detection scripts.
    """
        commands_textedit.setPlainText(commands_text)

        popup_window.exec_()

    def start_scan(self):
            host = self.host_input.text()
            basic_options = self.scan_options_input.text()

            if not host:
                QMessageBox.warning(self, "Error", "Please specify a target host.")
                return

            # Check if any of the entered options require root privilege
            options_require_root = any(option in ['-sS', '-O'] for option in basic_options.split())

            # Check if "Run as root" is selected
            if options_require_root and not self.run_as_root_checkbox.isChecked():
                QMessageBox.warning(self, "Error", "The selected scan options require root privileges. "
                                                   "Please check the 'Run as root' checkbox.")
                return

            # Construct basic Nmap command
            nmap_cmd = ["nmap", host]
            if basic_options:
                nmap_cmd.extend(basic_options.split())

            # Add advanced options
            advanced_options = []
            if self.os_detection_checkbox.isChecked():
                advanced_options.append("-O")  # Add OS detection
            if self.service_version_checkbox.isChecked():
                advanced_options.append("-sV")  # Add service version detection
            # Add more advanced options as needed

            # Merge basic and advanced options
            nmap_cmd.extend(advanced_options)

            # Run as root if selected
            if self.run_as_root_checkbox.isChecked():
                # Use sudo to run the Nmap command with root privileges
                sudo_cmd = ["sudo", "-S"]  # -S option tells sudo to read the password from stdin
                sudo_cmd.extend(nmap_cmd)
                try:
                    self.nmap_process = subprocess.Popen(sudo_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                         stderr=subprocess.PIPE, text=True)
                    stdout, stderr = self.nmap_process.communicate(
                        input=self.get_password() + '\n')  # Prompt for password
                    self.output_area.append(stdout.strip())
                    if stderr:
                        QMessageBox.critical(self, "Error", f"Error: {stderr.strip()}")

                except Exception as e:
                    print("Error running Nmap command:", str(e))  # Debugging statement
                    QMessageBox.critical(self, "Error", f"Error: {str(e)}")
            else:
                # Run Nmap command without root privileges
                try:
                    self.nmap_process = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                         text=True)
                    self.show_message("Scan started...\n")
                    self.scan_button.setDisabled(True)
                    self.stop_button.setEnabled(True)
                    self.read_output()
                    self.add_to_scan_history(host, basic_options)

                except Exception as e:
                    print("Error running Nmap command:", str(e))  # Debugging statement
                    QMessageBox.critical(self, "Error", f"Error: {str(e)}")

            # Inform the user about limited features if not running as root
            if not self.run_as_root_checkbox.isChecked() and not self.user_has_sudo_nopasswd():
                QMessageBox.warning(self, "Limited Features",
                                    "Running without root privileges. Some features may be limited.")

    def get_password(self):
        # Prompt the user to enter the password
        # Returns the entered password or None if the user cancels
        password, ok = QInputDialog.getText(self, 'Password', 'Enter your password:', QLineEdit.Password)
        if ok:
            return password
        else:
            return None

    def user_has_sudo_nopasswd(self):
        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(['sudo', '-n', 'nmap', '--version'], stdout=devnull, stderr=devnull)
            return True
        except subprocess.CalledProcessError:
            return False


    def stop_scan(self):
        if self.nmap_process and self.nmap_process.poll() is None:
            self.nmap_process.terminate()
            self.nmap_process.wait()  # Wait for the process to terminate
            self.show_message("Scan stopped.\n")

        # Enable buttons
        self.scan_button.setEnabled(True)
        self.stop_button.setDisabled(True)

    def read_output(self):
        password_prompt_encountered = False  # Flag to track if password prompt has been encountered
        while True:
            line = self.nmap_process.stdout.readline()
            if "Starting Nmap" in line:  # Reset flag when a new scan starts
                password_prompt_encountered = False
            if line.strip() and not password_prompt_encountered:  # Check the flag before appending the line
                self.output_area.append(line.strip())
            if "[sudo] password" in line:  # Set flag if password prompt is encountered
                password_prompt_encountered = True
            if not line and self.nmap_process.poll() is not None:
                break

    def show_message(self, message):
        self.output_area.append(message)

    def add_to_scan_history(self, host, options):
        # Create a dictionary to store scan information
        scan_info = {
            "Host": host,
            "Options": options
        }
        # Append the dictionary to the scan history list
        self.scan_history.append(scan_info)

        # Update the list widget with the new scan information
        self.update_scan_history_list()

    def update_scan_history_list(self):
        # Clear the existing items in the scan history list widget
        self.scan_history_list.clear()

        # Add each scan info to the list widget
        for scan_info in self.scan_history:
            host = scan_info["Host"]
            options = scan_info["Options"]
            scan_info_str = f"Host: {host}, Options: {options}"
            self.scan_history_list.addItem(scan_info_str)

    def export_scan_results(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "", "CSV Files (*.csv)")

        if filename:
            with open(filename, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Host", "Port", "Service"])
                text = self.output_area.toPlainText()
                host = None  # Initialize host variable
                for line in text.split("\n"):
                    if line.startswith("Nmap scan report for"):
                        host = line.split()[-1]
                    elif line.startswith("PORT"):
                        continue
                    elif line.strip() and "/" in line and host:  # Check if host is not None
                        parts = line.split("/")
                        port = parts[0]
                        service = "/".join(parts[1:])  # Join remaining parts into service
                        writer.writerow([host, port, service])

    def clear_fields(self):
        # Clear input fields
        self.host_input.clear()
        self.scan_options_input.clear()

    def toggle_theme(self):
        if self.styleSheet() == "":
            self.set_dark_mode()
            self.edit_toggle_action.setText("Toggle Light Mode")
        else:
            self.set_light_mode()
            self.edit_toggle_action.setText("Toggle Dark Mode")

    def set_dark_mode(self):
        self.setStyleSheet("""
                    /* Dark mode stylesheet */
                    QMainWindow {
                        background-color: #212121;
                    }
                    /* Add styles for other widgets as needed */
                    QMessageBox {
                        background-color: #333; /* Dark background color */
                    }
                    QMessageBox QLabel {
                        color: #FFF; /* White text color */
                    }
                """)

    def set_light_mode(self):
        self.setStyleSheet("")

    def save_scan_configuration(self):
        # Prompt user to choose the location to save the configuration
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog  # Add this line to disable native dialog
        filename, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "", "Config Files (*.cfg)",
                                                  options=options)

        if filename:
            # Ensure the file has the ".cfg" extension
            if not filename.endswith(".cfg"):
                filename += ".cfg"

            # Save the configuration to the chosen file location
            with open(filename, "w") as f:
                f.write(f"Host: {self.host_input.text()}\n")
                f.write(f"Scan Options: {self.scan_options_input.text()}\n")
                f.write(f"OS Detection: {self.os_detection_checkbox.isChecked()}\n")
                f.write(f"Service Version Detection: {self.service_version_checkbox.isChecked()}\n")
                f.write(f"Run as Root: {self.run_as_root_checkbox.isChecked()}\n")

            QMessageBox.information(self, "Configuration Saved", "Configuration saved successfully.")

    def load_scan_configuration(self):
        # Prompt the user to select the configuration file to load
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog  # Add this line to disable native dialog
        filename, _ = QFileDialog.getOpenFileName(self, "Load Configuration", "", "Config Files (*.cfg)",
                                                  options=options)

        if filename:
            # Read the configuration from the selected file
            with open(filename, "r") as f:
                lines = f.readlines()

            # Parse the configuration and update the GUI accordingly
            for line in lines:
                if line.startswith("Host:"):
                    host = line.split(":")[1].strip()
                    self.host_input.setText(host)
                elif line.startswith("Scan Options:"):
                    options = line.split(":")[1].strip()
                    self.scan_options_input.setText(options)
                elif line.startswith("OS Detection:"):
                    os_detection = line.split(":")[1].strip().lower() == "true"
                    self.os_detection_checkbox.setChecked(os_detection)
                elif line.startswith("Service Version Detection:"):
                    service_version = line.split(":")[1].strip().lower() == "true"
                    self.service_version_checkbox.setChecked(service_version)
                elif line.startswith("Run as Root:"):
                    run_as_root = line.split(":")[1].strip().lower() == "true"
                    self.run_as_root_checkbox.setChecked(run_as_root)

            QMessageBox.information(self, "Configuration Loaded", "Configuration loaded successfully.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())