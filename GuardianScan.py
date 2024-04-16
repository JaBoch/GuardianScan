import sys
import subprocess
import csv
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QLineEdit,
                             QTextEdit, QListWidget, QAction, QFileDialog, QCheckBox, QMessageBox, QSplitter, QDialog, QProgressBar)
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt
import os

class NmapGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Guardian Scan")
        self.setGeometry(100, 100, 1000, 600)
        self.scan_history = []  # Initialize scan history list

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
        self.scan_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; border-radius: 5px; }")
        self.scan_button.clicked.connect(self.start_scan)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setFont(QFont("Arial", 12))
        self.stop_button.setStyleSheet("QPushButton { background-color: #f44336; color: white; border-radius: 5px; }")
        self.stop_button.setDisabled(True)
        self.stop_button.clicked.connect(self.stop_scan)

        self.clear_button = QPushButton("Clear Fields")
        self.clear_button.setFont(QFont("Arial", 12))
        self.clear_button.setStyleSheet("QPushButton { background-color: #ff9800; color: white; border-radius: 5px; }")
        self.clear_button.clicked.connect(self.clear_fields)

        self.dark_mode = False  # Add a flag to track the theme mode

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)

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
        left_layout.addWidget(self.clear_button)
        left_layout.addWidget(self.progress_bar)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        # Create output area
        self.output_label = QLabel("Scan Results:")
        self.output_label.setFont(QFont("Arial", 12))
        self.output_area = QTextEdit()
        self.output_area.setFont(QFont("Arial", 10))
        self.output_area.setReadOnly(True)

        self.scan_history_label = QLabel("Scan History:")
        self.scan_history_label.setFont(QFont("Arial", 12))
        self.scan_history_list = QListWidget()
        self.scan_history_list.setFont(QFont("Arial", 10))

        right_layout = QVBoxLayout()
        right_layout.addWidget(self.output_label)
        right_layout.addWidget(self.output_area)
        right_layout.addWidget(self.scan_history_label)
        right_layout.addWidget(self.scan_history_list)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        splitter = QSplitter()
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        self.setCentralWidget(splitter)

        # Menu bar
        self.setupMenus()

    def setupMenus(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        export_action = QAction("Export Scan Results", self)
        export_action.triggered.connect(self.export_scan_results)
        file_menu.addAction(export_action)

        save_config_action = QAction("Save Scan Configuration", self)
        save_config_action.triggered.connect(self.save_scan_configuration)
        file_menu.addAction(save_config_action)

        load_config_action = QAction("Load Scan Configuration", self)
        load_config_action.triggered.connect(self.load_scan_configuration)
        file_menu.addAction(load_config_action)

        help_menu = menubar.addMenu("Help")
        nmap_commands_action = QAction("Nmap Commands", self)
        nmap_commands_action.triggered.connect(self.show_nmap_commands)
        help_menu.addAction(nmap_commands_action)

        edit_menu = menubar.addMenu("Edit")
        self.edit_toggle_action = QAction("Toggle Dark Mode", self)
        self.edit_toggle_action.triggered.connect(self.toggle_theme)
        edit_menu.addAction(self.edit_toggle_action)

    def add_to_scan_history(self, host, options):
        # Format the string to display in the scan history list
        scan_info = f"Host: {host}, Options: {options}"
        # Append the formatted string to the scan history list
        self.scan_history.append(scan_info)
        # Update the QListWidget to display the new entry
        self.update_scan_history_list()

    def update_scan_history_list(self):
        # Clear the list to avoid duplication
        self.scan_history_list.clear()
        # Populate the list with updated history
        for history_item in self.scan_history:
            self.scan_history_list.addItem(history_item)

    def start_scan(self):
        host = self.host_input.text()
        options = self.scan_options_input.text()
        if not host:
            QMessageBox.warning(self, "Error", "Please specify a target host.")
            return

        nmap_cmd = self.construct_nmap_command(host, options)
        if self.run_as_root_checkbox.isChecked() and not self.user_has_sudo_nopasswd():
            QMessageBox.information(self, "Root Privilege Required",
                                    "Please run the GUI with root privileges or set up password-less sudo for Nmap.")
            return

        self.execute_nmap_command(nmap_cmd)
    def construct_nmap_command(self, host, basic_options):
        nmap_cmd = ["nmap", host]
        if basic_options:
            nmap_cmd.extend(basic_options.split())
        if self.os_detection_checkbox.isChecked():
            nmap_cmd.append("-O")
        if self.service_version_checkbox.isChecked():
            nmap_cmd.append("-sV")
        return nmap_cmd

    def execute_nmap_command(self, nmap_cmd):
        if self.run_as_root_checkbox.isChecked():
            nmap_cmd = ["sudo"] + nmap_cmd
        try:
            self.nmap_process = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
            self.scan_button.setDisabled(True)
            self.stop_button.setEnabled(True)
            self.progress_bar.setValue(0)
            self.read_output()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error running Nmap command: {str(e)}")

    def user_has_sudo_nopasswd(self):
        try:
            subprocess.check_call(['sudo', '-n', 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def read_output(self):
        # Assuming you collect and process scan output here
        output = ""
        while True:
            line = self.nmap_process.stdout.readline()
            if line == "":
                break
            output += line
            self.output_area.append(line.strip())

        # Once the scan is done, update the progress, buttons, and scan history
        self.scan_button.setEnabled(True)
        self.stop_button.setDisabled(True)
        self.progress_bar.setValue(100)  # Assuming scan completes at 100%
        # Add scan to history
        self.add_to_scan_history(self.host_input.text(), self.scan_options_input.text())

    def stop_scan(self):
        if self.nmap_process and self.nmap_process.poll() is None:
            self.nmap_process.terminate()
            self.nmap_process.wait()
            QMessageBox.information(self, "Scan Stopped", "The Nmap scan has been successfully stopped.")
        self.scan_button.setEnabled(True)
        self.stop_button.setDisabled(True)
        self.progress_bar.setValue(0)  # Reset progress bar when scan is stopped

    def clear_fields(self):
        self.host_input.clear()
        self.scan_options_input.clear()

    def toggle_theme(self):
        if not self.dark_mode:
            self.set_dark_mode()
            self.edit_toggle_action.setText("Toggle Light Mode")
            self.dark_mode = True
        else:
            self.set_light_mode()
            self.edit_toggle_action.setText("Toggle Dark Mode")
            self.dark_mode = False

    def set_dark_mode(self):
        self.setStyleSheet("""
            QMainWindow, QLabel, QCheckBox, QTextEdit, QLineEdit, QListWidget, QProgressBar, QSplitter::handle {
                background-color: #212121;
                color: #E0E0E0;
            }
            QPushButton {
                background-color: #4CAF50;
                color: #FFFFFF;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
            QPushButton:disabled {
                background-color: #A5D6A7;
                color: #333333;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #333333;
                color: #FFFFFF;
                border: 1px solid #4CAF50;
            }
            QMessageBox {
                background-color: #424242;
                color: #FFFFFF;
            }
        """)

    def set_light_mode(self):
        self.setStyleSheet("""
            QMainWindow, QLabel, QCheckBox, QTextEdit, QLineEdit, QListWidget, QProgressBar, QSplitter::handle {
                background-color: #FFFFFF;
                color: #000000;
            }
            QPushButton {
                background-color: #F0F0F0;
                color: #000000;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
            }
            QPushButton:pressed {
                background-color: #C0C0C0;
            }
            QPushButton:disabled {
                background-color: #E0E0E0;
                color: #A0A0A0;
            }
            QMessageBox {
                background-color: #FFFFFF;
                color: #000000;
            }
        """)
    def export_scan_results(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "", "CSV Files (*.csv)")

        if filename:
            with open(filename, "w", newline='') as csvfile:
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

    def save_scan_configuration(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "", "Config Files (*.cfg)", options=options)

        if filename:
            if not filename.endswith('.cfg'):
                filename += '.cfg'
            try:
                with open(filename, "w") as file:
                    file.write(f"Host: {self.host_input.text()}\n")
                    file.write(f"Scan Options: {self.scan_options_input.text()}\n")
                    file.write(f"OS Detection: {self.os_detection_checkbox.isChecked()}\n")
                    file.write(f"Service Version Detection: {self.service_version_checkbox.isChecked()}\n")
                    file.write(f"Run as Root: {self.run_as_root_checkbox.isChecked()}\n")
                QMessageBox.information(self, "Configuration Saved", f"Configuration saved successfully to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")

    def load_scan_configuration(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getOpenFileName(self, "Load Configuration", "", "Config Files (*.cfg)", options=options)

        if filename:
            try:
                with open(filename, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        if line.startswith("Host:"):
                            self.host_input.setText(line.split(":", 1)[1].strip())
                        elif line.startswith("Scan Options:"):
                            self.scan_options_input.setText(line.split(":", 1)[1].strip())
                        elif line.startswith("OS Detection:"):
                            self.os_detection_checkbox.setChecked(line.split(":", 1)[1].strip().lower() == 'true')
                        elif line.startswith("Service Version Detection:"):
                            self.service_version_checkbox.setChecked(line.split(":", 1)[1].strip().lower() == 'true')
                        elif line.startswith("Run as Root:"):
                            self.run_as_root_checkbox.setChecked(line.split(":", 1)[1].strip().lower() == 'true')
                QMessageBox.information(self, "Configuration Loaded", f"Configuration loaded successfully from {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load configuration: {str(e)}")

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
        commands_text = """Nmap Commands:

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())