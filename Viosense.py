import sys
import traceback
import hashlib
from datetime import date
import mysql.connector
from mysql.connector import Error

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QWidget,
    QHBoxLayout, QVBoxLayout, QFrame, QMessageBox, QFormLayout, QDialog,
    QDialogButtonBox, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont

def get_db_connection(host="localhost", user="root", password="", database="viosense"):
    return mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        auth_plugin="mysql_native_password"
    )

def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

class UserDialog(QDialog):
    def __init__(self, parent=None, user=None):
        super().__init__(parent)
        self.user = user
        self.setModal(True)
        self.resize(480, 240)
        self.setWindowTitle("Edit User" if user else "Add User")

        form = QFormLayout()
        self.username_edit = QLineEdit()
        self.fullname_edit = QLineEdit()
        self.plate_edit = QLineEdit()
        self.role_combo = QComboBox()
        self.role_combo.addItems(["user", "admin"])
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Set password (leave empty to keep)")
        form.addRow("Username:", self.username_edit)
        form.addRow("Full name:", self.fullname_edit)
        form.addRow("Plate number:", self.plate_edit)
        form.addRow("Role:", self.role_combo)
        form.addRow("Password:", self.password_edit)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(btns)
        self.setLayout(layout)

        if user:
            self.username_edit.setText(user.get("username", ""))
            self.username_edit.setDisabled(True)
            self.fullname_edit.setText(user.get("full_name", ""))
            self.plate_edit.setText(user.get("plate_number", ""))
            role = user.get("role", "user")
            self.role_combo.setCurrentIndex(0 if role == "user" else 1)

    def get_data(self):
        return {
            "username": self.username_edit.text().strip(),
            "full_name": self.fullname_edit.text().strip(),
            "plate_number": self.plate_edit.text().strip(),
            "role": self.role_combo.currentText().strip(),
            "password": self.password_edit.text()
        }

class PaymentDialog(QDialog):
    def __init__(self, violation, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pay Violation")
        self.violation = violation
        layout = QVBoxLayout()
        info = (f"Violation #{violation['violation_id']}\n"
                f"Fine: {violation['fine_charged']}\n"
                f"Type: {violation['violation_type']}\n")
        layout.addWidget(QLabel(info))
        self.payment_select = QComboBox()
        self.payment_select.addItems(["Credit", "GCash", "PayMaya"])
        layout.addWidget(QLabel("Select payment method:"))
        layout.addWidget(self.payment_select)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        self.setLayout(layout)

    def get_method(self):
        return self.payment_select.currentText()

class ReceiptDialog(QDialog):
    def __init__(self, violation, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Payment Receipt")
        self.resize(400, 300)
        layout = QVBoxLayout()
        info = (
            "<b>Payment Receipt</b><br><hr>"
            f"<b>Violation ID:</b> {violation['violation_id']}<br>"
            f"<b>Driver Name:</b> {violation['driver_name']}<br>"
            f"<b>License Plate:</b> {violation['license_plate']}<br>"
            f"<b>Violation Type:</b> {violation['violation_type']}<br>"
            f"<b>Date Recorded:</b> {violation['date_recorded']}<br>"
            f"<b>Fine Charged:</b> {violation['fine_charged']}<br>"
            f"<b>Vehicle Model:</b> {violation['vehicle_model']}<br>"
            f"<b>Status:</b> {violation['status']}<br>"
            f"<b>Payment Method:</b> {violation.get('payment_method','')}<br>"
            "<br><b>-- Ready to Print --</b>"
        )
        label = QLabel()
        label.setTextFormat(Qt.TextFormat.RichText)
        label.setText(info)
        layout.addWidget(label)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(self.accept)
        layout.addWidget(btns)
        self.setLayout(layout)

class FineGuideDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Fine Guide List")
        self.resize(420, 380)
        layout = QVBoxLayout()
        table = QTableWidget()
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT violation_name, fine_amount FROM fine_dictionary ORDER BY violation_name")
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception as e:
            rows = []
            QMessageBox.warning(self, "Error", f"Could not load fine guide: {e}")
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Violation Type", "Fine Amount"])
        table.setRowCount(len(rows))
        for idx, r in enumerate(rows):
            table.setItem(idx, 0, QTableWidgetItem(r["violation_name"]))
            table.setItem(idx, 1, QTableWidgetItem(f"{r['fine_amount']:.2f}"))
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(table)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(self.accept)
        layout.addWidget(btns)
        self.setLayout(layout)

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VioSense - Login")
        self.resize(960, 640)
        self.signup_window = None
        self.dashboard_window = None
        self._build_ui()
        self.setStyleSheet(self._styles())

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        sidebar = QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setStyleSheet("QFrame { background-color: #7f2b2b; }")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(28, 28, 28, 28)
        logo = QLabel("VioSense")
        
        logo.setFont(QFont("Arial", 48, QFont.Weight.Bold))
        logo.setStyleSheet("color: white; font-size: 48px; font-weight: bold;")
        subtitle = QLabel("Traffic Violation Management")
        subtitle.setStyleSheet("color: #f0dede;")
        sb_layout.addWidget(logo)
        sb_layout.addWidget(subtitle)
        sb_layout.addStretch(1)
        sb_layout.addWidget(QLabel("© 2025 VioSense"), alignment=Qt.AlignmentFlag.AlignBottom)

        card = QFrame()
        card.setFixedWidth(520)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(36, 36, 36, 36)

        t = QLabel("VIOSENSE")
        # --- Bigger font for WELCOME BACK ---
        t.setFont(QFont("Arial", 50, QFont.Weight.Bold))
        t.setStyleSheet("font-size: 48px; font-weight: bold; color: #2c3e50;")
        sub = QLabel("Sign in to your VioSense account")
        sub.setStyleSheet("color: #7f8c8d;")

        self.input_username = QLineEdit()
        self.input_username.setPlaceholderText("Username")
        self.input_password = QLineEdit()
        self.input_password.setPlaceholderText("Password")
        self.input_password.setEchoMode(QLineEdit.EchoMode.Password)

        btn_login = QPushButton("Login")
        btn_login.clicked.connect(self.handle_login)

        btn_go_signup = QPushButton("Go to Sign Up")
        btn_go_signup.setFlat(True)
        btn_go_signup.clicked.connect(self.open_signup_window)

        row = QHBoxLayout()
        row.addWidget(btn_login)
        row.addWidget(btn_go_signup)

        self.login_status = QLabel("")
        self.login_status.setStyleSheet("color: #b03a2e;")

        card_layout.addWidget(t, alignment=Qt.AlignmentFlag.AlignLeft)
        card_layout.addWidget(sub, alignment=Qt.AlignmentFlag.AlignLeft)
        card_layout.addSpacing(12)
        card_layout.addWidget(self.input_username)
        card_layout.addWidget(self.input_password)
        card_layout.addLayout(row)
        card_layout.addWidget(self.login_status)

        layout.addWidget(sidebar)
        layout.addStretch(1)
        layout.addWidget(card)
        layout.addStretch(1)

    def open_signup_window(self):
        if self.signup_window is None:
            self.signup_window = SignUpWindow(parent=self)
        self.signup_window.show()
        self.hide()

    def handle_login(self):
        username = self.input_username.text().strip()
        password = self.input_password.text()
        if not username or not password:
            self.login_status.setText("Please provide username and password.")
            return
        hashed = sha256_hash(password)
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            query = "SELECT id, username, full_name, plate_number, role FROM Users WHERE username = %s AND password_hash = %s"
            cursor.execute(query, (username, hashed))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
        except Error as e:
            self.login_status.setText("DB error. Check connection.")
            QMessageBox.critical(self, "Database Error", f"{e}")
            traceback.print_exc()
            return

        if user:
            self.open_dashboard(user)
        else:
            self.login_status.setText("Invalid username or password.")

    def open_dashboard(self, user_row):
        self.dashboard_window = DashboardWindow(user_row, parent=self)
        self.dashboard_window.show()
        self.hide()

    def show(self):
        super().show()
        self.raise_()
        self.activateWindow()

    def _styles(self):
        primary = "#c0392b"
        pdark = "#a93226"
        light = "#f9f5f4"
        neutral = "#2c3e50"
        # Remove/adjust QLabel font-size if needed to avoid override
        return f"""
            QWidget {{ background-color: {light}; color: {neutral}; font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }}
            QLineEdit, QComboBox {{ background: white; border: 1px solid #e5e5e5; border-radius: 5px; padding: 6px; }}
            QPushButton {{ background-color: {primary}; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; }}
            QPushButton:hover {{ background-color: #a93226; }}
            QPushButton:flat {{ background: none; color: {primary}; text-decoration: underline; }}
        """

class SignUpWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_login = parent
        self.setWindowTitle("VioSense - Sign Up")
        self.resize(760, 540)
        self._build_ui()
        self.setStyleSheet(self._styles())

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        sidebar = QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setStyleSheet("QFrame { background-color: #7f2b2b; }")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(28, 28, 28, 28)
        logo = QLabel("🚗 VioSense")
        logo.setFont(QFont("", 22, QFont.Weight.Bold))
        logo.setStyleSheet("color: white;")
        sb_layout.addWidget(logo)
        sb_layout.addStretch(1)
        sb_layout.addWidget(QLabel("© 2024 VioSense"), alignment=Qt.AlignmentFlag.AlignBottom)

        card = QFrame()
        card.setFixedWidth(520)
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(36, 36, 36, 36)

        title = QLabel("CREATE NEW ACCOUNT")
        title.setFont(QFont("", 16, QFont.Weight.Bold))
        sub = QLabel("Register a new VioSense user")
        sub.setStyleSheet("color: #7f8c8d;")

        self.su_username = QLineEdit(); self.su_username.setPlaceholderText("Choose a username")
        self.su_fullname = QLineEdit(); self.su_fullname.setPlaceholderText("Full name")
        self.su_plate = QLineEdit(); self.su_plate.setPlaceholderText("Plate number")
        self.su_password = QLineEdit(); self.su_password.setPlaceholderText("Password"); self.su_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.su_role = QComboBox(); self.su_role.addItems(["user", "admin"])

        btn_signup = QPushButton("Sign Up")
        btn_signup.clicked.connect(self.handle_signup)
        btn_back = QPushButton("Back to Login")
        btn_back.setFlat(True)
        btn_back.clicked.connect(self.back_to_login)

        row = QHBoxLayout()
        row.addWidget(btn_signup)
        row.addWidget(btn_back)

        self.signup_status = QLabel("")
        self.signup_status.setStyleSheet("color: #b03a2e;")

        c_layout.addWidget(title)
        c_layout.addWidget(sub)
        c_layout.addSpacing(10)
        c_layout.addWidget(self.su_username)
        c_layout.addWidget(self.su_fullname)
        c_layout.addWidget(self.su_plate)
        c_layout.addWidget(self.su_password)
        c_layout.addWidget(self.su_role)
        c_layout.addLayout(row)
        c_layout.addWidget(self.signup_status)

        layout.addWidget(sidebar)
        layout.addStretch(1)
        layout.addWidget(card)
        layout.addStretch(1)

    def handle_signup(self):
        username = self.su_username.text().strip()
        fullname = self.su_fullname.text().strip()
        plate = self.su_plate.text().strip()
        password = self.su_password.text()
        role = self.su_role.currentText()

        if not username or not fullname or not password:
            self.signup_status.setText("Username, full name, and password are required.")
            return

        hashed = sha256_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = "INSERT INTO Users (username, password_hash, full_name, plate_number, role) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (username, hashed, fullname, plate, role))
            conn.commit()
            cursor.close()
            conn.close()
            self.signup_status.setStyleSheet("color: green;")
            self.signup_status.setText("Account created successfully. You can login now.")
            self.su_username.clear(); self.su_fullname.clear(); self.su_plate.clear(); self.su_password.clear()
        except Error as e:
            self.signup_status.setStyleSheet("color: #b03a2e;")
            self.signup_status.setText(f"Error: {e}")
            traceback.print_exc()

    def back_to_login(self):
        if self.parent_login:
            self.parent_login.show()
        self.close()

    def _styles(self):
        primary = "#c0392b"
        pdark = "#a93226"
        light = "#f9f5f4"
        neutral = "#2c3e50"
        return f"""
            QWidget {{ background-color: {light}; color: {neutral}; font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }}
            QLineEdit {{ background: white; border: 1px solid #e5e5e5; border-radius: 5px; padding: 6px; }}
            QPushButton {{ background-color: {primary}; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; }}
            QPushButton:hover {{ background-color: #a93226; }}
            QPushButton:flat {{ background: none; color: {primary}; text-decoration: underline; }}
        """
class SignUpWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_login = parent
        self.setWindowTitle("VioSense - Sign Up")
        self.resize(760, 540)
        self._build_ui()
        self.setStyleSheet(self._styles())

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        sidebar = QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setStyleSheet("QFrame { background-color: #7f2b2b; }")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(28, 28, 28, 28)
        logo = QLabel(" VioSense")
        logo.setFont(QFont("", 22, QFont.Weight.Bold))
        logo.setStyleSheet("color: white;")
        sb_layout.addWidget(logo)
        sb_layout.addStretch(1)
        sb_layout.addWidget(QLabel("© 2025 VioSense"), alignment=Qt.AlignmentFlag.AlignBottom)

        card = QFrame()
        card.setFixedWidth(520)
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(36, 36, 36, 36)

        title = QLabel("CREATE NEW ACCOUNT")
        title.setFont(QFont("", 16, QFont.Weight.Bold))
        sub = QLabel("Register a new VioSense user")
        sub.setStyleSheet("color: #7f8c8d;")

        self.su_username = QLineEdit(); self.su_username.setPlaceholderText("Choose a username")
        self.su_fullname = QLineEdit(); self.su_fullname.setPlaceholderText("Full name")
        self.su_plate = QLineEdit(); self.su_plate.setPlaceholderText("Plate number")
        self.su_password = QLineEdit(); self.su_password.setPlaceholderText("Password"); self.su_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.su_role = QComboBox(); self.su_role.addItems(["user", "admin"])

        btn_signup = QPushButton("Sign Up")
        btn_signup.clicked.connect(self.handle_signup)
        btn_back = QPushButton("Back to Login")
        btn_back.setFlat(True)
        btn_back.clicked.connect(self.back_to_login)

        row = QHBoxLayout()
        row.addWidget(btn_signup)
        row.addWidget(btn_back)

        self.signup_status = QLabel("")
        self.signup_status.setStyleSheet("color: #b03a2e;")

        c_layout.addWidget(title)
        c_layout.addWidget(sub)
        c_layout.addSpacing(10)
        c_layout.addWidget(self.su_username)
        c_layout.addWidget(self.su_fullname)
        c_layout.addWidget(self.su_plate)
        c_layout.addWidget(self.su_password)
        c_layout.addWidget(self.su_role)
        c_layout.addLayout(row)
        c_layout.addWidget(self.signup_status)

        layout.addWidget(sidebar)
        layout.addStretch(1)
        layout.addWidget(card)
        layout.addStretch(1)

    def handle_signup(self):
        username = self.su_username.text().strip()
        fullname = self.su_fullname.text().strip()
        plate = self.su_plate.text().strip()
        password = self.su_password.text()
        role = self.su_role.currentText()

        if not username or not fullname or not password:
            self.signup_status.setText("Username, full name, and password are required.")
            return

        hashed = sha256_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = "INSERT INTO Users (username, password_hash, full_name, plate_number, role) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (username, hashed, fullname, plate, role))
            conn.commit()
            cursor.close()
            conn.close()
            self.signup_status.setStyleSheet("color: green;")
            self.signup_status.setText("Account created successfully. You can login now.")
            self.su_username.clear(); self.su_fullname.clear(); self.su_plate.clear(); self.su_password.clear()
        except Error as e:
            self.signup_status.setStyleSheet("color: #b03a2e;")
            self.signup_status.setText(f"Error: {e}")
            traceback.print_exc()

    def back_to_login(self):
        if self.parent_login:
            self.parent_login.show()
        self.close()

    def _styles(self):
        primary = "#c0392b"
        pdark = "#a93226"
        light = "#f9f5f4"
        neutral = "#2c3e50"
        return f"""
            QWidget {{ background-color: {light}; color: {neutral}; font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }}
            QLineEdit {{ background: white; border: 1px solid #e5e5e5; border-radius: 5px; padding: 6px; }}
            QPushButton {{ background-color: {primary}; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; }}
            QPushButton:hover {{ background-color: #a93226; }}
            QPushButton:flat {{ background: none; color: {primary}; text-decoration: underline; }}
        """
class EditProfileDialog(QDialog):
    def __init__(self, user, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Profile")
        self.resize(400, 220)
        self.user = user
        layout = QFormLayout()

        self.fullname_edit = QLineEdit(user.get("full_name", ""))
        self.plate_edit = QLineEdit(user.get("plate_number", ""))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Change password (leave empty to keep current)")

        layout.addRow("Full Name:", self.fullname_edit)
        layout.addRow("Plate Number:", self.plate_edit)
        layout.addRow("New Password:", self.password_edit)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)
        self.setLayout(layout)

    def get_data(self):
        return {
            "full_name": self.fullname_edit.text().strip(),
            "plate_number": self.plate_edit.text().strip(),
            "password": self.password_edit.text()
        }

class DashboardWindow(QMainWindow):
    def __init__(self, user_row: dict, parent=None):
        super().__init__(parent)
        self.user = {
            "id": user_row.get("id"),
            "username": user_row.get("username"),
            "full_name": user_row.get("full_name"),
            "plate_number": user_row.get("plate_number"),
            "role": user_row.get("role")
        }
        self.setWindowTitle(f"VioSense Dashboard - {self.user.get('username')}")
        self.resize(1200, 820)
        self.login_win = parent
        self._build_ui()
        self.setStyleSheet(self._styles())
        self.load_violations()
        if self.user.get("role", "").lower() == "admin":
            self.load_users()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 0)

        top = QFrame()
        top.setFixedHeight(64)
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(12, 8, 12, 0)
        btn_style = "QPushButton { background-color: #c0392b; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; } QPushButton:hover { background-color: #a93226; }"
        btn_profile = QPushButton("Profile")
        btn_profile.setStyleSheet(btn_style)
        btn_profile.clicked.connect(self.show_profile)
        btn_edit_profile = QPushButton("Edit Profile")
        btn_edit_profile.setStyleSheet(btn_style)
        btn_edit_profile.clicked.connect(self.edit_profile)
        btn_logout = QPushButton("Logout")
        btn_logout.setStyleSheet(btn_style)
        btn_logout.clicked.connect(self.logout)
        top_layout.addWidget(btn_profile)
        top_layout.addWidget(btn_edit_profile)
        top_layout.addWidget(btn_logout)
        self.lbl_welcome = QLabel(f"Welcome, {self.user.get('full_name') or self.user.get('username')} — Role: {self.user.get('role')}")
        self.lbl_welcome.setFont(QFont("", 12, QFont.Weight.Bold))
        top_layout.addWidget(self.lbl_welcome)
        top_layout.addStretch(1)
        layout.addWidget(top)

        body = QFrame()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        nav = QFrame()
        nav.setFixedWidth(260)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(12, 12, 12, 12)
        nav_layout.setSpacing(24)
        nav_btn_style = "QPushButton { background-color: #c0392b; color: white; border-radius: 8px; min-width: 220px; min-height: 36px; font-size: 13px; } QPushButton:hover { background-color: #a93226; }"
        self.btn_records = QPushButton("View Violations")
        self.btn_records.setStyleSheet(nav_btn_style)
        self.btn_records.clicked.connect(self.show_records)
        nav_layout.addWidget(self.btn_records, alignment=Qt.AlignmentFlag.AlignTop)
        self.btn_fine_guide = QPushButton("Fine Guide List")
        self.btn_fine_guide.setStyleSheet(nav_btn_style)
        self.btn_fine_guide.clicked.connect(self.show_fine_guide)
        nav_layout.addWidget(self.btn_fine_guide, alignment=Qt.AlignmentFlag.AlignTop)
        if self.user.get("role", "").lower() == "admin":
            self.btn_issue = QPushButton("Issue Violation")
            self.btn_issue.setStyleSheet(nav_btn_style)
            self.btn_issue.clicked.connect(self.show_issue)
            nav_layout.addWidget(self.btn_issue, alignment=Qt.AlignmentFlag.AlignTop)
            self.btn_users = QPushButton("Manage Users (Admin)")
            self.btn_users.setStyleSheet(nav_btn_style)
            self.btn_users.clicked.connect(self.show_manage_users)
            nav_layout.addWidget(self.btn_users, alignment=Qt.AlignmentFlag.AlignTop)
        nav_layout.addStretch(1)

        content = QFrame()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(12, 12, 12, 12)

        self.table_violations = QTableWidget()
        self.table_violations.setColumnCount(10)
        self.table_violations.setHorizontalHeaderLabels([
            "ID", "Driver Name", "License Plate", "Violation Type",
            "Date Recorded", "Fine Charged", "Vehicle Model", "Status", "Payment Method", "Action"
        ])
        self.table_violations.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.issue_widget = QFrame()
        issue_form = QFormLayout()
        self.driver_edit = QLineEdit()
        self.license_edit = QLineEdit()
        self.violation_type_edit = QComboBox()
        self.fine_edit = QLineEdit()
        self.fine_edit.setReadOnly(True)
        self.date_edit = QLineEdit()
        self.vehicle_model_edit = QLineEdit()
        self.load_violation_types_and_fines()
        self.violation_type_edit.currentIndexChanged.connect(self.update_fine_field)
        btn_save_ticket = QPushButton("Save Citation"); btn_save_ticket.clicked.connect(self.save_ticket)
        issue_form.addRow("Driver name:", self.driver_edit)
        issue_form.addRow("License plate:", self.license_edit)
        issue_form.addRow("Violation type:", self.violation_type_edit)
        issue_form.addRow("Fine charged:", self.fine_edit)
        issue_form.addRow("Date recorded (YYYY-MM-DD):", self.date_edit)
        issue_form.addRow("Vehicle model:", self.vehicle_model_edit)
        issue_form.addRow("", btn_save_ticket)
        iw_layout = QVBoxLayout(self.issue_widget)
        iw_layout.addLayout(issue_form)

        self.users_widget = QFrame()
        self.table_users = QTableWidget()
        self.table_users.setColumnCount(4)
        self.table_users.setHorizontalHeaderLabels(["Username", "Full name", "Plate", "Role"])
        self.table_users.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        users_btn_row = QHBoxLayout()
        btn_add = QPushButton("Add User"); btn_add.clicked.connect(self.add_user)
        btn_edit = QPushButton("Edit Selected"); btn_edit.clicked.connect(self.edit_user)
        btn_delete = QPushButton("Delete Selected"); btn_delete.clicked.connect(self.delete_user)
        users_btn_row.addWidget(btn_add); users_btn_row.addWidget(btn_edit); users_btn_row.addWidget(btn_delete)
        uw_layout = QVBoxLayout(self.users_widget)
        uw_layout.addWidget(self.table_users)
        uw_layout.addLayout(users_btn_row)

        content_layout.addWidget(self.table_violations)
        content_layout.addWidget(self.issue_widget)
        content_layout.addWidget(self.users_widget)

        self.table_violations.show()
        self.issue_widget.hide()
        self.users_widget.hide()

        body_layout.addWidget(nav)
        body_layout.addWidget(content)
        layout.addWidget(body)

    def edit_profile(self):
        dlg = EditProfileDialog(self.user, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                if data["password"]:
                    hashed = sha256_hash(data["password"])
                    cursor.execute(
                        "UPDATE Users SET full_name=%s, plate_number=%s, password_hash=%s WHERE username=%s",
                        (data["full_name"], data["plate_number"], hashed, self.user["username"])
                    )
                else:
                    cursor.execute(
                        "UPDATE Users SET full_name=%s, plate_number=%s WHERE username=%s",
                        (data["full_name"], data["plate_number"], self.user["username"])
                    )
                conn.commit()
                cursor.close()
                conn.close()
                self.user["full_name"] = data["full_name"]
                self.user["plate_number"] = data["plate_number"]
                self.lbl_welcome.setText(
                    f"Welcome, {self.user.get('full_name') or self.user.get('username')} — Role: {self.user.get('role')}"
                )
                QMessageBox.information(self, "Profile Updated", "Your profile has been updated.")
            except Exception as e:
                traceback.print_exc()
                QMessageBox.critical(self, "Update Error", f"Could not update profile:\n{e}")

class DashboardWindow(QMainWindow):
    def __init__(self, user_row: dict, parent=None):
        super().__init__(parent)
        self.user = {
            "id": user_row.get("id"),
            "username": user_row.get("username"),
            "full_name": user_row.get("full_name"),
            "plate_number": user_row.get("plate_number"),
            "role": user_row.get("role")
        }
        self.setWindowTitle(f"VioSense Dashboard - {self.user.get('username')}")
        self.resize(1200, 820)
        self.login_win = parent
        self._build_ui()
        self.setStyleSheet(self._styles())
        self.load_violations()
        if self.user.get("role", "").lower() == "admin":
            self.load_users()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 0)

        top = QFrame()
        top.setFixedHeight(64)
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(12, 8, 12, 0)
        btn_style = "QPushButton { background-color: #c0392b; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; } QPushButton:hover { background-color: #a93226; }"
        btn_profile = QPushButton("Profile")
        btn_profile.setStyleSheet(btn_style)
        btn_profile.clicked.connect(self.show_profile)
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(btn_style)
        btn_refresh.clicked.connect(self.load_violations)
        btn_logout = QPushButton("Logout")
        btn_logout.setStyleSheet(btn_style)
        btn_logout.clicked.connect(self.logout)
        top_layout.addWidget(btn_profile)
        top_layout.addWidget(btn_refresh)
        top_layout.addWidget(btn_logout)
        self.lbl_welcome = QLabel(f"Welcome, {self.user.get('full_name') or self.user.get('username')} — Role: {self.user.get('role')}")
        self.lbl_welcome.setFont(QFont("", 12, QFont.Weight.Bold))
        top_layout.addWidget(self.lbl_welcome)
        top_layout.addStretch(1)
        layout.addWidget(top)

        body = QFrame()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        nav = QFrame()
        nav.setFixedWidth(260)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(12, 12, 12, 12)
        nav_layout.setSpacing(24)
        nav_btn_style = "QPushButton { background-color: #c0392b; color: white; border-radius: 8px; min-width: 220px; min-height: 36px; font-size: 13px; } QPushButton:hover { background-color: #a93226; }"
        self.btn_records = QPushButton("View Violations")
        self.btn_records.setStyleSheet(nav_btn_style)
        self.btn_records.clicked.connect(self.show_records)
        nav_layout.addWidget(self.btn_records, alignment=Qt.AlignmentFlag.AlignTop)
        self.btn_fine_guide = QPushButton("Fine Guide List")
        self.btn_fine_guide.setStyleSheet(nav_btn_style)
        self.btn_fine_guide.clicked.connect(self.show_fine_guide)
        nav_layout.addWidget(self.btn_fine_guide, alignment=Qt.AlignmentFlag.AlignTop)
        if self.user.get("role", "").lower() == "admin":
            self.btn_issue = QPushButton("Issue Violation")
            self.btn_issue.setStyleSheet(nav_btn_style)
            self.btn_issue.clicked.connect(self.show_issue)
            nav_layout.addWidget(self.btn_issue, alignment=Qt.AlignmentFlag.AlignTop)
            self.btn_users = QPushButton("Manage Users (Admin)")
            self.btn_users.setStyleSheet(nav_btn_style)
            self.btn_users.clicked.connect(self.show_manage_users)
            nav_layout.addWidget(self.btn_users, alignment=Qt.AlignmentFlag.AlignTop)
        nav_layout.addStretch(1)

        content = QFrame()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(12, 12, 12, 12)

        self.table_violations = QTableWidget()
        self.table_violations.setColumnCount(10)
        self.table_violations.setHorizontalHeaderLabels([
            "ID", "Driver Name", "License Plate", "Violation Type",
            "Date Recorded", "Fine Charged", "Vehicle Model", "Status", "Payment Method", "Action"
        ])
        self.table_violations.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.issue_widget = QFrame()
        issue_form = QFormLayout()
        self.driver_edit = QLineEdit()
        self.license_edit = QLineEdit()
        self.violation_type_edit = QComboBox()
        self.fine_edit = QLineEdit()
        self.fine_edit.setReadOnly(True)
        self.date_edit = QLineEdit()
        self.vehicle_model_edit = QLineEdit()
        self.load_violation_types_and_fines()
        self.violation_type_edit.currentIndexChanged.connect(self.update_fine_field)
        btn_save_ticket = QPushButton("Save Citation"); btn_save_ticket.clicked.connect(self.save_ticket)
        issue_form.addRow("Driver name:", self.driver_edit)
        issue_form.addRow("License plate:", self.license_edit)
        issue_form.addRow("Violation type:", self.violation_type_edit)
        issue_form.addRow("Fine charged:", self.fine_edit)
        issue_form.addRow("Date recorded (YYYY-MM-DD):", self.date_edit)
        issue_form.addRow("Vehicle model:", self.vehicle_model_edit)
        issue_form.addRow("", btn_save_ticket)
        iw_layout = QVBoxLayout(self.issue_widget)
        iw_layout.addLayout(issue_form)

        self.users_widget = QFrame()
        self.table_users = QTableWidget()
        self.table_users.setColumnCount(4)
        self.table_users.setHorizontalHeaderLabels(["Username", "Full name", "Plate", "Role"])
        self.table_users.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        users_btn_row = QHBoxLayout()
        btn_add = QPushButton("Add User"); btn_add.clicked.connect(self.add_user)
        btn_edit = QPushButton("Edit Selected"); btn_edit.clicked.connect(self.edit_user)
        btn_delete = QPushButton("Delete Selected"); btn_delete.clicked.connect(self.delete_user)
        users_btn_row.addWidget(btn_add); users_btn_row.addWidget(btn_edit); users_btn_row.addWidget(btn_delete)
        uw_layout = QVBoxLayout(self.users_widget)
        uw_layout.addWidget(self.table_users)
        uw_layout.addLayout(users_btn_row)

        content_layout.addWidget(self.table_violations)
        content_layout.addWidget(self.issue_widget)
        content_layout.addWidget(self.users_widget)

        self.table_violations.show()
        self.issue_widget.hide()
        self.users_widget.hide()

        body_layout.addWidget(nav)
        body_layout.addWidget(content)
        layout.addWidget(body)

    def show_fine_guide(self):
        dlg = FineGuideDialog(self)
        dlg.exec()

    def load_violation_types_and_fines(self):
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT violation_name, fine_amount FROM fine_dictionary")
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Load Error", f"Could not load violation types:\n{e}")
            rows = []
        self.violation_types_fines = {r['violation_name']: r['fine_amount'] for r in rows}
        self.violation_type_edit.clear()
        self.violation_type_edit.addItems(list(self.violation_types_fines.keys()))
        self.update_fine_field()

    def update_fine_field(self):
        vtype = self.violation_type_edit.currentText()
        fine = self.violation_types_fines.get(vtype, "")
        self.fine_edit.setText(str(fine))

    def show_records(self):
        self.table_violations.show(); self.issue_widget.hide(); self.users_widget.hide()

    def show_issue(self):
        self.table_violations.hide(); self.issue_widget.show(); self.users_widget.hide()
        if self.user.get("plate_number"):
            self.license_edit.setText(self.user.get("plate_number"))

    def show_manage_users(self):
        self.table_violations.hide(); self.issue_widget.hide(); self.users_widget.show()
        self.load_users()

    def load_violations(self):
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            if self.user.get("role", "").lower() == "admin":
                cursor.execute("""
                    SELECT violation_id, driver_name, license_plate, violation_type,
                           date_recorded, fine_charged, vehicle_model, status, payment_method
                    FROM Violations
                    ORDER BY violation_id DESC LIMIT 500
                """)
            else:
                cursor.execute("""
                    SELECT violation_id, driver_name, license_plate, violation_type,
                           date_recorded, fine_charged, vehicle_model, status, payment_method
                    FROM Violations
                    WHERE license_plate = %s
                    ORDER BY violation_id DESC LIMIT 500
                """, (self.user.get("plate_number"),))
            rows = cursor.fetchall()
            cursor.close(); conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Load Error", f"Could not load violations:\n{e}")
            rows = []

        self.table_violations.setRowCount(0)
        for r in rows:
            idx = self.table_violations.rowCount()
            self.table_violations.insertRow(idx)
            self.table_violations.setItem(idx, 0, QTableWidgetItem(str(r.get("violation_id", ""))))
            self.table_violations.setItem(idx, 1, QTableWidgetItem(r.get("driver_name", "")))
            self.table_violations.setItem(idx, 2, QTableWidgetItem(r.get("license_plate", "")))
            self.table_violations.setItem(idx, 3, QTableWidgetItem(r.get("violation_type", "")))
            self.table_violations.setItem(idx, 4, QTableWidgetItem(str(r.get("date_recorded", ""))))
            self.table_violations.setItem(idx, 5, QTableWidgetItem(str(r.get("fine_charged", ""))))
            self.table_violations.setItem(idx, 6, QTableWidgetItem(r.get("vehicle_model", "")))
            status_item = QTableWidgetItem(r.get("status", ""))
            if r.get("status", "") == "Paid":
                status_item.setBackground(Qt.GlobalColor.green)
                status_item.setForeground(Qt.GlobalColor.white)
            self.table_violations.setItem(idx, 7, status_item)
            self.table_violations.setItem(idx, 8, QTableWidgetItem(str(r.get("payment_method", ""))))
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0,0,0,0)
            if self.user.get("role", "").lower() == "user" and r.get("status", "") == "Unpaid":
                btn_pay = QPushButton("Pay")
                btn_pay.setStyleSheet("background-color: #27ae60; color: white;")
                btn_pay.clicked.connect(lambda _, v=r: self.open_payment_dialog(v))
                action_layout.addWidget(btn_pay)
            elif r.get("status", "") == "Paid":
                lbl_paid = QLabel("Paid")
                lbl_paid.setStyleSheet("color: #27ae60; font-weight:bold;")
                action_layout.addWidget(lbl_paid)
            action_layout.addStretch(1)
            self.table_violations.setCellWidget(idx, 9, action_widget)

    def open_payment_dialog(self, violation):
        pdialog = PaymentDialog(violation, self)
        if pdialog.exec() == QDialog.DialogCode.Accepted:
            method = pdialog.get_method()
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE Violations SET status='Paid', payment_method=%s WHERE violation_id=%s
                """, (method, violation['violation_id']))
                conn.commit()
                cursor.close(); conn.close()
                violation['status'] = 'Paid'
                violation['payment_method'] = method
                self.load_violations()
                dlg = ReceiptDialog(violation, parent=self)
                dlg.exec()
            except Exception as e:
                traceback.print_exc()
                QMessageBox.critical(self, "Payment Error", f"Could not process payment:\n{e}")

    def save_ticket(self):
        driver_name = self.driver_edit.text().strip()
        license_plate = self.license_edit.text().strip()
        violation_type = self.violation_type_edit.currentText()
        fine_charged = self.fine_edit.text().strip()
        date_recorded = self.date_edit.text().strip()
        vehicle_model = self.vehicle_model_edit.text().strip()
        status = "Unpaid"
        payment_method = None
        try:
            if not date_recorded:
                date_recorded = date.today().strftime("%Y-%m-%d")
            else:
                year, month, day = map(int, date_recorded.split("-"))
                date_recorded = date(year, month, day).strftime("%Y-%m-%d")
        except Exception as e:
            QMessageBox.warning(self, "Date Error", "Date format should be YYYY-MM-DD.")
            return

        if not driver_name or not license_plate or not violation_type or not fine_charged:
            QMessageBox.warning(self, "Input required", "Fill all required fields.")
            return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO Violations (
                    driver_name, license_plate, violation_type,
                    date_recorded, fine_charged, vehicle_model, status, payment_method
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                driver_name, license_plate, violation_type,
                date_recorded, fine_charged, vehicle_model, status, payment_method
            ))
            conn.commit(); cursor.close(); conn.close()
            QMessageBox.information(self, "Saved", "Violation citation recorded.")
            self.driver_edit.clear()
            self.license_edit.clear()
            self.violation_type_edit.setCurrentIndex(0)
            self.fine_edit.clear()
            self.date_edit.clear()
            self.vehicle_model_edit.clear()
            self.load_violations(); self.show_records()
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "Save Error", f"Could not save citation:\n{e}")

    def load_users(self):
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, full_name, plate_number, role FROM Users ORDER BY username")
            rows = cursor.fetchall()
            cursor.close(); conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Load Users", f"Could not load users:\n{e}")
            rows = []

        self.table_users.setRowCount(0)
        for u in rows:
            r = self.table_users.rowCount()
            self.table_users.insertRow(r)
            self.table_users.setItem(r, 0, QTableWidgetItem(u.get("username", "")))
            self.table_users.setItem(r, 1, QTableWidgetItem(u.get("full_name", "")))
            self.table_users.setItem(r, 2, QTableWidgetItem(u.get("plate_number", "")))
            self.table_users.setItem(r, 3, QTableWidgetItem(u.get("role", "")))

    def add_user(self):
        dlg = UserDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if not data["username"] or not data["password"]:
                QMessageBox.warning(self, "Input", "Username and password are required.")
                return
            hashed = sha256_hash(data["password"])
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO Users (username, password_hash, full_name, plate_number, role) VALUES (%s, %s, %s, %s, %s)",
                               (data["username"], hashed, data["full_name"], data["plate_number"], data["role"]))
                conn.commit(); cursor.close(); conn.close()
                QMessageBox.information(self, "Added", "User added.")
                self.load_users()
            except Exception as e:
                traceback.print_exc()
                QMessageBox.critical(self, "Add Error", f"Could not add user:\n{e}")

    def edit_user(self):
        sel = self.table_users.selectedItems()
        if not sel:
            QMessageBox.information(self, "Select", "Select a user row first.")
            return
        username = sel[0].text()
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, full_name, plate_number, role FROM Users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close(); conn.close()
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "Fetch Error", f"Could not fetch user:\n{e}")
            return
        if not user:
            QMessageBox.warning(self, "Not found", "User not found.")
            return
        dlg = UserDialog(self, user=user)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                if data["password"]:
                    hashed = sha256_hash(data["password"])
                    cursor.execute("UPDATE Users SET password_hash=%s, full_name=%s, plate_number=%s, role=%s WHERE username=%s",
                                   (hashed, data["full_name"], data["plate_number"], data["role"], username))
                else:
                    cursor.execute("UPDATE Users SET full_name=%s, plate_number=%s, role=%s WHERE username=%s",
                                   (data["full_name"], data["plate_number"], data["role"], username))
                conn.commit(); cursor.close(); conn.close()
                QMessageBox.information(self, "Updated", "User updated.")
                self.load_users()
            except Exception as e:
                traceback.print_exc()
                QMessageBox.critical(self, "Update Error", f"Could not update user:\n{e}")

    def delete_user(self):
        sel = self.table_users.selectedItems()
        if not sel:
            QMessageBox.information(self, "Select", "Select a user row first.")
            return
        username = sel[0].text()
        if username == self.user.get("username"):
            QMessageBox.warning(self, "Forbidden", "Cannot delete currently logged in account.")
            return
        confirm = QMessageBox.question(self, "Delete", f"Delete user '{username}'? This cannot be undone.")
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM Users WHERE username = %s", (username,))
            conn.commit(); cursor.close(); conn.close()
            QMessageBox.information(self, "Deleted", "User deleted.")
            self.load_users()
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "Delete Error", f"Could not delete user:\n{e}")

    def show_profile(self):
        info = (
            f"Username: {self.user.get('username')}\n"
            f"Full name: {self.user.get('full_name')}\n"
            f"Plate number: {self.user.get('plate_number')}\n"
            f"Role: {self.user.get('role')}"
        )
        QMessageBox.information(self, "Profile", info)

    def logout(self):
        confirm = QMessageBox.question(self, "Logout", "Are you sure you want to logout?")
        if confirm == QMessageBox.StandardButton.Yes:
            self.close()
            if self.login_win:
                self.login_win.show()
                self.login_win.raise_()
                self.login_win.activateWindow()
            else:
                login = LoginWindow()
                login.show()

    def _styles(self):
        primary = "#c0392b"
        pdark = "#a93226"
        light = "#f9f5f4"
        neutral = "#2c3e50"
        return f"""
            QWidget {{ background-color: {light}; color: {neutral}; font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }}
            QLineEdit, QComboBox {{ background: white; border: 1px solid #e5e5e5; border-radius: 5px; padding: 6px; }}
            QPushButton {{ background-color: {primary}; color: white; border-radius: 8px; min-width: 100px; min-height: 36px; font-size: 13px; }}
            QPushButton:hover {{ background-color: #a93226; }}
            QPushButton:flat {{ background: none; color: {primary}; text-decoration: underline; }}
        """

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login = LoginWindow()
    login.show()
    sys.exit(app.exec())
