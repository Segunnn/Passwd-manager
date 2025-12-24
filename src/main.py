import sys
import os
import sqlite3

import base64
import hashlib
from hmac import compare_digest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QListWidget, QListWidgetItem, QStackedWidget, 
                             QTextEdit, QMessageBox, QSplitter, QFrame)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QIcon

PPPIIINNN = ""

# --- SECURITY MANAGER (Placeholder) ---
class SecurityManager:
    PINHASH_FILENAME = ".pinc"
    SALT_SIZE = 16
    ITERATIONS = 200_000

    @staticmethod
    def encrypt(plain_text):
        master_key = SecurityManager.get_encryption_key(PPPIIINNN)
        cipher = Fernet(master_key)
        return cipher.encrypt(plain_text.encode()).decode()

    @staticmethod
    def decrypt(cipher_text):
        master_key = SecurityManager.get_encryption_key(PPPIIINNN)
        cipher = Fernet(master_key)
        return cipher.decrypt(cipher_text.encode()).decode()

    @staticmethod
    def setup_pin(pin: str):
        salt = os.urandom(SecurityManager.SALT_SIZE)
        
        key = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode('utf-8'),
            salt,
            SecurityManager.ITERATIONS
        )

        with open(SecurityManager.PINHASH_FILENAME, "wb") as f:
            f.write(salt + key)

    @staticmethod
    def verify_pin(pin: str):
        if not os.path.exists(SecurityManager.PINHASH_FILENAME):
            return False

        with open(SecurityManager.PINHASH_FILENAME, "rb") as f:
            data = f.read()
            
        salt = data[:SecurityManager.SALT_SIZE]
        stored_hash = data[SecurityManager.SALT_SIZE:]

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode('utf-8'),
            salt,
            SecurityManager.ITERATIONS
        )

        return compare_digest(stored_hash, new_hash)

    @staticmethod
    def get_encryption_key(pin: str):
        with open(SecurityManager.PINHASH_FILENAME, "rb") as f:
            salt = f.read(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SecurityManager.ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(pin.encode()))


# --- DATABASE MANAGER ---
class DatabaseManager:
    def __init__(self, db_name=".pmdbpm.db"):
        self.db_name = db_name
        self.init_db()

    def connect(self):
        return sqlite3.connect(self.db_name)

    def init_db(self):
        with self.connect() as conn:
            cursor = conn.cursor()
            # Updated Schema based on requirements
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource TEXT NOT NULL,
                    login TEXT,
                    gmail TEXT,
                    password TEXT NOT NULL,
                    note TEXT
                )
            """)
            conn.commit()

    def add_entry(self, resource, login, gmail, password, note):
        enc_pass = SecurityManager.encrypt(password)
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credentials (resource, login, gmail, password, note) 
                VALUES (?, ?, ?, ?, ?)""",
                (resource, login, gmail, enc_pass, note))
            conn.commit()

    def update_entry(self, entry_id, resource, login, gmail, password, note):
        enc_pass = SecurityManager.encrypt(password)
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE credentials 
                SET resource=?, login=?, gmail=?, password=?, note=? 
                WHERE id=?""",
                (resource, login, gmail, enc_pass, note, entry_id))
            conn.commit()

    def get_all_entries(self):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, resource, login, gmail, password, note FROM credentials")
            rows = cursor.fetchall()
        
        return rows

    def delete_entry(self, entry_id):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE id = ?", (entry_id,))
            conn.commit()


def restart_application():
    python = sys.executable
    os.execl(python, python, *sys.argv)

# --- CUSTOM WIDGETS ---

class StyledLineEdit(QLineEdit):
    """Helper to create consistent inputs"""
    def __init__(self, placeholder, is_password=False):
        super().__init__()
        self.setPlaceholderText(placeholder)
        if is_password:
            self.setEchoMode(QLineEdit.EchoMode.Password)

class LoginWindow(QWidget):
    def __init__(self, on_success_callback):
        super().__init__()
        self.on_success = on_success_callback
        self.setup_ui()
        
    def setup_ui(self):
        if not os.path.exists(".pinc"):
            layout = QVBoxLayout(self)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            title = QLabel("LOCKED")
            title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e0e0e0; margin-bottom: 5px;")
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)

            self.pin_input = StyledLineEdit("Enter PIN", is_password=True)
            self.pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.pin_input.setFixedWidth(200)
            self.pin_input.returnPressed.connect(self.create_pin)

            login_btn = QPushButton("Save new PIN")
            login_btn.setFixedWidth(200)
            login_btn.clicked.connect(self.create_pin)
        
            layout.addWidget(title)
            layout.addWidget(self.pin_input)
            layout.addWidget(login_btn)

            return None

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("LOCKED")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e0e0e0; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.pin_input = StyledLineEdit("Enter PIN", is_password=True)
        self.pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pin_input.setFixedWidth(200)
        self.pin_input.returnPressed.connect(self.check_pin)
        
        login_btn = QPushButton("Unlock")
        login_btn.setFixedWidth(200)
        login_btn.clicked.connect(self.check_pin)
        
        layout.addWidget(title)
        layout.addWidget(self.pin_input)
        layout.addWidget(login_btn)

    def create_pin(self):
        SecurityManager.setup_pin(self.pin_input.text())
        restart_application()

    def check_pin(self):
        # HARDCODED PIN FOR DEMO
        if SecurityManager.verify_pin(self.pin_input.text()):
            self.on_success()
            global PPPIIINNN
            PPPIIINNN = self.pin_input.text()
        else:
            self.pin_input.setStyleSheet("border: 1px solid #ff4444;")
            self.pin_input.clear()
            self.pin_input.setPlaceholderText("Wrong PIN")

# --- MAIN APP UI ---

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.setWindowTitle("Password Vault")
        self.resize(900, 600)
        self.apply_dark_theme()
        
        # Stack to switch between Login and App
        self.main_stack = QStackedWidget()
        self.setCentralWidget(self.main_stack)
        
        # 1. Login Screen
        self.login_screen = LoginWindow(self.unlock_app)
        self.main_stack.addWidget(self.login_screen)
        
        # 2. Main App Screen (Split View)
        self.app_widget = QWidget()
        self.app_layout = QHBoxLayout(self.app_widget)
        self.app_layout.setContentsMargins(0,0,0,0)
        
        # Splitter to divide Left (List) and Right (Details)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # --- LEFT SIDE SETUP ---
        self.left_container = QWidget()
        self.left_layout = QVBoxLayout(self.left_container)
        self.left_layout.setContentsMargins(0,0,0,0)
        
        # Stack for Left Side: Index 0 = List, Index 1 = Add/Edit Form
        self.left_stack = QStackedWidget()
        
        # Left View 0: List + Add Button
        self.list_view_widget = QWidget()
        self.list_view_layout = QVBoxLayout(self.list_view_widget)
        self.resource_list = QListWidget()
        self.resource_list.itemClicked.connect(self.display_details)
        
        self.add_btn_main = QPushButton("+ Add Resource")
        self.add_btn_main.setFixedHeight(40)
        self.add_btn_main.clicked.connect(self.show_add_form)
        
        self.list_view_layout.addWidget(self.resource_list)
        self.list_view_layout.addWidget(self.add_btn_main)
        
        # Left View 1: Form (Add/Edit)
        self.form_widget = QWidget()
        self.form_layout = QVBoxLayout(self.form_widget)
        
        self.inp_resource = StyledLineEdit("Resource Name (Required)")
        self.inp_login = StyledLineEdit("Login / Username")
        self.inp_gmail = StyledLineEdit("Gmail / Email")
        self.inp_pass = StyledLineEdit("Password (Required)", is_password=True)
        self.inp_pass_toggle = QPushButton("Show")
        self.inp_pass_toggle.setCheckable(True)
        self.inp_pass_toggle.clicked.connect(self.toggle_form_password)
        
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(self.inp_pass)
        pass_layout.addWidget(self.inp_pass_toggle)

        self.inp_note = QTextEdit()
        self.inp_note.setPlaceholderText("Notes...")
        self.inp_note.setMaximumHeight(100)
        
        self.btn_save = QPushButton("Save")
        self.btn_save.clicked.connect(self.save_data)
        self.btn_save.setStyleSheet("background-color: #8EBBFF;")
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.cancel_form)
        self.btn_cancel.setStyleSheet("background-color: #555;")
        
        btn_row = QHBoxLayout()
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.btn_cancel)
        
        self.form_layout.addWidget(QLabel("Resource Info"))
        self.form_layout.addWidget(self.inp_resource)
        self.form_layout.addWidget(self.inp_login)
        self.form_layout.addWidget(self.inp_gmail)
        self.form_layout.addLayout(pass_layout)
        self.form_layout.addWidget(self.inp_note)
        self.form_layout.addLayout(btn_row)
        self.form_layout.addStretch()
        
        self.left_stack.addWidget(self.list_view_widget)
        self.left_stack.addWidget(self.form_widget)
        
        self.left_layout.addWidget(self.left_stack)
        
        # --- RIGHT SIDE SETUP ---
        self.right_container = QWidget()
        self.right_layout = QVBoxLayout(self.right_container)
        
        # Stack for Right Side: Index 0 = Blank, Index 1 = Details
        self.right_stack = QStackedWidget()
        
        # Right View 0: Blank / Placeholder
        placeholder = QLabel("Select a resource to view details")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #777; font-size: 16px;")
        self.right_stack.addWidget(placeholder)
        
        # Right View 1: Details
        self.details_view = QWidget()
        self.details_layout = QVBoxLayout(self.details_view)
        
        self.lbl_title = QLabel("Resource Name")
        self.lbl_title.setStyleSheet("font-size: 22px; font-weight: bold; color: #fff;")
        
        # Detail items container
        self.info_container = QWidget()
        info_layout = QVBoxLayout(self.info_container)
        
        self.det_login = QLabel()
        self.det_gmail = QLabel()
        self.det_note = QLabel()
        self.det_note.setWordWrap(True)
        
        # Password Display area
        pass_display_layout = QHBoxLayout()
        self.det_password_display = QLineEdit()
        self.det_password_display.setReadOnly(True)
        self.det_password_display.setEchoMode(QLineEdit.EchoMode.Password)
        self.det_password_display.setStyleSheet("background: transparent; border: none; font-size: 16px;")
        
        self.btn_toggle_view_pass = QPushButton("Show")
        self.btn_toggle_view_pass.setFixedWidth(60)
        self.btn_toggle_view_pass.clicked.connect(self.toggle_view_password)
        
        pass_display_layout.addWidget(QLabel("Password: "))
        pass_display_layout.addWidget(self.det_password_display)
        pass_display_layout.addWidget(self.btn_toggle_view_pass)
        
        info_layout.addWidget(QLabel("Login:"))
        info_layout.addWidget(self.det_login)
        info_layout.addWidget(self.make_divider())
        info_layout.addWidget(QLabel("Gmail:"))
        info_layout.addWidget(self.det_gmail)
        info_layout.addWidget(self.make_divider())
        info_layout.addLayout(pass_display_layout)
        info_layout.addWidget(self.make_divider())
        info_layout.addWidget(QLabel("Note:"))
        info_layout.addWidget(self.det_note)
        info_layout.addStretch()

        # Bottom Buttons (Edit/Delete)
        bottom_btns = QHBoxLayout()
        self.btn_edit = QPushButton("Edit")
        self.btn_edit.clicked.connect(self.edit_current_resource)
        self.btn_delete = QPushButton("Delete")
        self.btn_delete.setStyleSheet("background-color: #8B3232;")
        self.btn_delete.clicked.connect(self.delete_current_resource)
        
        bottom_btns.addWidget(self.btn_edit)
        bottom_btns.addWidget(self.btn_delete)
        
        self.details_layout.addWidget(self.lbl_title)
        self.details_layout.addWidget(self.make_divider())
        self.details_layout.addWidget(self.info_container)
        self.details_layout.addLayout(bottom_btns)
        
        self.right_stack.addWidget(self.details_view)
        
        self.right_layout.addWidget(self.right_stack)

        # Add to Splitter
        self.splitter.addWidget(self.left_container)
        self.splitter.addWidget(self.right_container)
        self.splitter.setSizes([300, 600]) # Initial widths
        self.splitter.setCollapsible(0, False)
        
        self.app_layout.addWidget(self.splitter)
        self.main_stack.addWidget(self.app_widget)

        # State Tracking
        self.current_editing_id = None
        self.current_selected_data = None

    def make_divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet("background-color: #444;")
        return line

    def unlock_app(self):
        self.main_stack.setCurrentIndex(1)
        self.load_resources_list()

    def show_add_form(self):
        # Clear fields
        self.current_editing_id = None
        self.inp_resource.clear()
        self.inp_login.clear()
        self.inp_gmail.clear()
        self.inp_pass.clear()
        self.inp_note.clear()
        
        # UI Toggles
        self.inp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_pass_toggle.setText("Show")
        self.inp_pass_toggle.setChecked(False)
        
        # Switch Left Panel
        self.left_stack.setCurrentIndex(1)

    def cancel_form(self):
        self.left_stack.setCurrentIndex(0)

    def toggle_form_password(self):
        if self.inp_pass_toggle.isChecked():
            self.inp_pass.setEchoMode(QLineEdit.EchoMode.Normal)
            self.inp_pass_toggle.setText("Hide")
        else:
            self.inp_pass.setEchoMode(QLineEdit.EchoMode.Password)
            self.inp_pass_toggle.setText("Show")

    def toggle_view_password(self):
        if self.det_password_display.text() == "*********":
            try:
                decrypted = SecurityManager.decrypt(self.current_encrypted_password)
                self.det_password_display.setText(decrypted)
                self.btn_toggle_view_pass.setText("Hide")
                self.det_password_display.setEchoMode(QLineEdit.EchoMode.Normal)
            except Exception:
                QMessageBox.critical(self, "Error!", "Unable to decrypt password")
        else:
            self.det_password_display.setText("*********")
            self.btn_toggle_view_pass.setText("Show")

    def save_data(self):
        res = self.inp_resource.text()
        login = self.inp_login.text()
        gmail = self.inp_gmail.text()
        pwd = self.inp_pass.text()
        note = self.inp_note.toPlainText()
        
        if not res or not pwd:
            QMessageBox.warning(self, "Missing Info", "Resource and Password are required.")
            return

        if self.current_editing_id:
            self.db.update_entry(self.current_editing_id, res, login, gmail, pwd, note)
            self.current_editing_id = None
        else:
            self.db.add_entry(res, login, gmail, pwd, note)
            
        self.load_resources_list()
        self.left_stack.setCurrentIndex(0) # Go back to list
        
        # If we were editing, refresh right side details, else clear right side
        if self.current_selected_data:
             # Refresh details for the currently selected ID if it still exists
             # For simplicity, we just clear the selection on save
             self.right_stack.setCurrentIndex(0)

    def load_resources_list(self):
        self.resource_list.clear()
        entries = self.db.get_all_entries()
        for entry in entries:
            # entry structure: id, resource, login, gmail, password, note
            item = QListWidgetItem(f"{entry[1]} ({entry[2] if entry[2] else entry[3]})") # Display Resource Name
            item.setData(Qt.ItemDataRole.UserRole, entry) # Store full data in item
            self.resource_list.addItem(item)

    def display_details(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        self.current_selected_data = data
        
        # Unpack
        e_id, resource, login, gmail, password, note = data

        self.current_encrypted_password = password
        
        self.lbl_title.setText(resource)
        self.det_login.setText(login if login else "-")
        self.det_gmail.setText(gmail if gmail else "-")
        self.det_note.setText(note if note else "No notes.")
        
        self.det_password_display.setText("*********")
        self.btn_toggle_view_pass.setText("Show")
        
        self.right_stack.setCurrentIndex(1)

    def edit_current_resource(self):
        if not self.current_selected_data: 
            return
            
        e_id, resource, login, gmail, password, note = self.current_selected_data
        
        self.current_editing_id = e_id
        
        self.inp_resource.setText(resource)
        self.inp_login.setText(login)
        self.inp_gmail.setText(gmail)
        self.inp_pass.setText(password)
        self.inp_note.setText(note)
        
        # Switch Left Panel to Form
        self.left_stack.setCurrentIndex(1)

    def delete_current_resource(self):
        if not self.current_selected_data:
            return
            
        confirm = QMessageBox.question(self, "Delete", "Are you sure?", 
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            self.db.delete_entry(self.current_selected_data[0])
            self.right_stack.setCurrentIndex(0) # Clear right side
            self.current_selected_data = None
            self.load_resources_list()

    def apply_dark_theme(self):
        style = """
            QMainWindow, QWidget { background-color: #161616; color: #e0e0e0; font-family: Segoe UI; }
            
            /* Inputs */
            QLineEdit, QTextEdit {
                background-color: #242426;
                color: #ffffff;
                border: 1px solid #161616;
                border-radius: 2px;
                padding: 6px;
                font-size: 11px;
            }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #888888; }
            
            /* Lists */
            QListWidget {
                background-color: #161616;
                border: none;
                font-size: 15px;
            }
            QListWidget::item { padding: 10px; border-bottom: 1px solid #444; }
            QListWidget::item:selected { background-color: #242426; color: white; }
            
            /* Buttons */
            QPushButton {
                background-color: #242426;
                color: white;
                border: none;
                border-radius: 2px;
                padding: 8px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #5a5a5a; }
            QPushButton:pressed { background-color: #3a3a3a; }
            
            /* Splitter Handle */
            QSplitter::handle { background-color: #202020; }
        """
        self.setStyleSheet(style)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
