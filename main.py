import base64
import re
import cryptography
import openai as openai
from cryptography.fernet import Fernet
import os
from kivy.app import App
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.properties import ObjectProperty
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.uix.dropdown import DropDown
from kivy.graphics import Color, Rectangle
from kivy.uix.image import Image
from pymongo import MongoClient


Builder.load_string('''
<Button>:
    background_color:(0,0,0,0)
    background_normal: ''
    canvas.before:
        Color:
            rgba: (0.576, 0.749, 0.812, 1)  # Set the background color to 93BFCF (RGB: 147, 191, 207)
        RoundedRectangle:
            size: self.size
            pos: self.pos
            radius: [15]  # Set the corner radius to 15
''')

class Button(Button):
    pass

encryption_key = b'pEBMpd7ZkQ1hlXBPeGApYIojdpZyPqy8B_3De4UEYPY='
cipher_suite = Fernet(encryption_key)
print(encryption_key)

employer_encryption_key = b'n0MJHLrCBcoJL-yKXUZzQr-K8N82K76rsnOL49BjAxc='
employer_cipher_suite = Fernet(employer_encryption_key)
print(employer_encryption_key)

# connect to MongoDB
client = MongoClient('mongodb://127.0.0.1:27017')
db = client['jobseeker_db']
employer_collection = db['employer']
employee_collection = db['employee']

class RBACManager:
    roles = {
        "admin": ["create", "read", "update", "delete"],
        "employer": ["create", "read", "update"],
        "user": ["read"]
    }

    @staticmethod
    def check_permission(role, permission):
        if role in RBACManager.roles:
            role_permissions = RBACManager.roles[role]
            return permission in role_permissions
        return False


class authenticate_user:
    def __init__(self):
        self.users = {}
        self.load_credentials()

    def load_credentials(self):
        with open('user_credentials.txt', 'r') as file:
            lines = file.readlines()

            i = 0
            while i < len(lines):
                if lines[i].startswith("Encrypted Employee Email: "):
                    encrypted_email = base64.b64decode(
                        lines[i].split(": ")[1].strip())
                    decrypted_email = cipher_suite.decrypt(
                        encrypted_email).decode('utf-8').strip()

                    encrypted_password = base64.b64decode(
                        lines[i+1].split(": ")[1].strip())
                    decrypted_password = cipher_suite.decrypt(
                        encrypted_password).decode('utf-8').strip()

                    self.users[cipher_suite.encrypt(decrypted_email.encode('utf-8'))] = {
                        "password": cipher_suite.encrypt(decrypted_password.encode('utf-8')), "role": "user"}

                    i += 3  # Skip the next two lines since we have already processed them
                else:
                    i += 1

    def authenticate(self, email, password):
        for user_email, user_data in self.users.items():
            decrypted_email = cipher_suite.decrypt(user_email).decode('utf-8')

            if email == decrypted_email:
                decrypted_password = cipher_suite.decrypt(
                    user_data["password"]).decode('utf-8')
                if password == decrypted_password:
                    role = user_data["role"]
                    return role if RBACManager.check_permission(role, "read") else None

        return None


class authenticate_employer:
    def __init__(self):
        self.users = {}
        self.load_credentials()

    def load_credentials(self):
        with open('employer_credentials.txt', 'r') as file:
            lines = file.readlines()

            i = 0
            while i < len(lines):
                if lines[i].startswith("Encrypted Employer Email: "):
                    encrypted_email = base64.b64decode(
                        lines[i].split(": ")[1].strip())
                    decrypted_email = None
                    try:
                        decrypted_email = employer_cipher_suite.decrypt(
                            encrypted_email).decode('utf-8').strip()
                    except cryptography.fernet.InvalidToken as e:
                        print("Error decrypting email:", e)

                    encrypted_password = base64.b64decode(
                        lines[i+1].split(": ")[1].strip())
                    decrypted_password = None
                    try:
                        decrypted_password = employer_cipher_suite.decrypt(
                            encrypted_password).decode('utf-8').strip()
                    except cryptography.fernet.InvalidToken as e:
                        print("Error decrypting password:", e)

                    if decrypted_email and decrypted_password:
                        self.users[employer_cipher_suite.encrypt(
                            decrypted_email.encode('utf-8'))] = {
                                "password": employer_cipher_suite.encrypt(decrypted_password.encode('utf-8')),
                                "role": "employer"
                        }

                    i += 3  # Skip the next two lines since we have already processed them
                else:
                    i += 1

    def authenticate(self, email, password):
        for employer_email, user_data in self.users.items():
            decrypted_email = employer_cipher_suite.decrypt(
                employer_email).decode('utf-8')

            if email == decrypted_email:
                decrypted_password = employer_cipher_suite.decrypt(
                    user_data["password"]).decode('utf-8')
                if password == decrypted_password:
                    role = user_data["role"]
                    return role if RBACManager.check_permission(role, "read") else None

        return None


class EmployerLoginScreen(Screen):
    def __init__(self, **kwargs):
        super(EmployerLoginScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        logo_image = Image(
            source='logo.jpeg',
            size_hint=(1,0.25),
            pos_hint={'center_x': 0.5, 'center_y': 0.8}
        )
        self.add_widget(logo_image)

        self.employer_label = Label(
            text='Employer',
            font_size=80,
            size_hint=(0.4, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='Dacherry',
            color=(0, 0, 0, 1),
        )
        self.add_widget(self.employer_label)

        # Create a text input widget for the email address
        self.email_input = TextInput(
            hint_text='Enter your email address',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            background_color=(217/255, 217/255, 217/255,1),
            background_active="",
            background_normal="",
            font_name='Arial',
        )
        self.add_widget(self.email_input)

        self.password_input = TextInput(
            hint_text='Enter your password',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            password=True
        )
        self.add_widget(self.password_input)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.23},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.continue_button = Button(
            text="Continue",
            size_hint=(0.65, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.3},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.continue_button.bind(on_press=self.continue_login)
        self.add_widget(self.continue_button)

        self.signup_button = Button(
            text="Register a new account",
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.17},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.signup_button.bind(on_press=self.signup_account)
        self.add_widget(self.signup_button)

        self.employee_button = Button(
            text='Login As Job Seeker',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.1},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.employee_button.bind(on_press=self.open_employee)
        self.add_widget(self.employee_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def continue_login(self,instance):
        email = self.email_input.text.strip()
        password = self.password_input.text.strip()

        auth = authenticate_employer()
        role = auth.authenticate(email, password)

        if email == '' or password == '':
            self.email_input.text = ""
            self.password_input.text = ""
            self.error_label.text = 'Please enter email and password.'
            self.email_input.bind(text=self.clear_error_message)
            self.password_input.bind(text=self.clear_error_message)
        else:
            if role == "user":
                screen_manager.current = 'homepage2'
                self.email_input.text = ""
                self.password_input.text = ""
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)
            elif role:
                self.email_input.text = ""
                self.password_input.text = ""
                self.error_label.text = "Access denied. You do not have permission to log in as an employer."
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)
            else:
                self.email_input.text = ""
                self.password_input.text = ""
                self.error_label.text = "Invalid email or password. Please try again."
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)

    def clear_error_message(self, instance, value):
        self.error_label.text = ''

    def signup_account(self,instance):
        screen_manager.current = 'signup2'
        self.error_label.text = ''

    def open_employee(self, instance):
        # Switch to the email input screen
        screen_manager.current = 'login1'
        self.error_label.text = ''

class EmployeeLoginScreen(Screen):
    def __init__(self, **kwargs):
        super(EmployeeLoginScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        logo_image = Image(
            source='logo.jpeg',
            size_hint=(1, 0.25),
            pos_hint={'center_x': 0.5, 'center_y': 0.8}
        )
        self.add_widget(logo_image)

        self.employee_label = Label(
            text='Job Seeker',
            font_size=80,
            size_hint=(0.4, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='SuperMario256',
            color = (0,0,0,1),
        )
        self.add_widget(self.employee_label)

        # Create a text input widget for the email address
        self.email_input = TextInput(
            hint_text='Enter your email address',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
        )
        self.add_widget(self.email_input)

        self.password_input = TextInput(
            hint_text='Enter your password',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            password=True
        )
        self.add_widget(self.password_input)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.23},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.continue_button = Button(
            text="Continue",
            size_hint=(0.65, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.3},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.continue_button.bind(on_press=self.continue_login)
        self.add_widget(self.continue_button)

        self.signup_button = Button(
            text="Register a new account",
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.17},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.signup_button.bind(on_press=self.signup_account)
        self.add_widget(self.signup_button)

        self.employer_button = Button(
            text='Login As Employer',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.1},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.employer_button.bind(on_press=self.open_employer)
        self.add_widget(self.employer_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def continue_login(self,instance):
        email = self.email_input.text.strip()
        password = self.password_input.text.strip()

        auth = authenticate_user()
        role = auth.authenticate(email, password)

        if email == '' or password == '':
            self.email_input.text = ""
            self.password_input.text = ""
            self.error_label.text = 'Please enter email and password.'
            self.email_input.bind(text=self.clear_error_message)
            self.password_input.bind(text=self.clear_error_message)
        else:
            if role == "user":
                screen_manager.current = 'homepage1'
                self.email_input.text = ""
                self.password_input.text = ""
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)
            elif role:
                self.email_input.text = ""
                self.password_input.text = ""
                self.error_label.text = "Access denied. You do not have permission to log in as an employee."
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)
            else:
                self.email_input.text = ""
                self.password_input.text = ""
                self.error_label.text = "Invalid email or password. Please try again."
                self.email_input.bind(text=self.clear_error_message)
                self.password_input.bind(text=self.clear_error_message)



    def clear_error_message(self, instance, value):
        self.error_label.text = ''

    def signup_account(self,instance):
        screen_manager.current = 'signup1'
        self.error_label.text = ''

    def open_employer(self, instance):
        # Switch to the employer screen
        screen_manager.current = 'login2'
        self.error_label.text = ''


class SignupJobSeekerScreen(Screen):
    def __init__(self, **kwargs):
        super(SignupJobSeekerScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        logo_image = Image(
            source='logo.jpeg',
            size_hint=(1, 0.25),
            pos_hint={'center_x': 0.5, 'center_y': 0.8}
        )
        self.add_widget(logo_image)

        self.employee_label = Label(
            text='Job Seeker',
            font_size=80,
            size_hint=(0.4, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='SuperMario256',
            color = (0,0,0,1),
        )
        self.add_widget(self.employee_label)

        # Create a text input widget for the email address
        self.email_input = TextInput(
            hint_text='Enter your email address',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
        )
        self.add_widget(self.email_input)

        self.password_input = TextInput(
            hint_text='Enter your password',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            password=True
        )
        self.add_widget(self.password_input)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.23},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.continue_button = Button(
            text="Sign Up",
            size_hint=(0.65, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.3},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.continue_button.bind(on_press=self.continue_signup)
        self.add_widget(self.continue_button)

        self.Login_button = Button(
            text="Login existing account",
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.15},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.Login_button.bind(on_press=self.Login_account)
        self.add_widget(self.Login_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def continue_signup(self,instance):
        email_employee = self.email_input.text
        password_employee = self.password_input.text

        encrypted_employee_email = cipher_suite.encrypt(
            email_employee.encode('utf-8'))
        encrypted_employee_password = cipher_suite.encrypt(
            password_employee.encode('utf-8'))
        
        # create an employee object to be inserted into mongodb
        employee = {
            "email":base64.b64encode(encrypted_employee_email).decode('utf-8'),
            "password":base64.b64encode(encrypted_employee_password).decode('utf-8')
        }

        employee_collection.insert_one(employee)

        if email_employee == '' or password_employee == '':
            self.error_label.text = 'Please enter email and password.'
        else:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email_employee):
                # Create a file and write the email and password to it
                with open('user_credentials.txt', 'a') as file:
                    file.write(
                        f"Encrypted Employee Email: {base64.b64encode(encrypted_employee_email).decode('utf-8')}\n")
                    file.write(
                        f"Encrypted Employee Password: {base64.b64encode(encrypted_employee_password).decode('utf-8')}\n\n")
                screen_manager.current = 'moreinfo1'
                self.email_input.text = ""
                self.password_input.text = ""
            else:
                self.error_label.text = 'Please enter a valid email.'

    def Login_account(self,instance):
        screen_manager.current = 'login1'

class SignupEmployerScreen(Screen):
    def __init__(self, **kwargs):
        super(SignupEmployerScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        logo_image = Image(
            source='logo.jpeg',
            size_hint=(1, 0.25),
            pos_hint={'center_x': 0.5, 'center_y': 0.8}
        )
        self.add_widget(logo_image)

        self.employer_label = Label(
            text='Employer',
            font_size=80,
            size_hint=(0.4, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='Dacherry',
            color = (0,0,0,1),
        )
        self.add_widget(self.employer_label)

        # Create a text input widget for the email address
        self.email_input = TextInput(
            hint_text='Enter your company email address',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
        )
        self.add_widget(self.email_input)

        self.password_input = TextInput(
            hint_text='Enter your password',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            password=True
        )
        self.add_widget(self.password_input)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.23},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.continue_button = Button(
            text="Sign Up",
            size_hint=(0.65, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.3},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.continue_button.bind(on_press=self.continue_signup)
        self.add_widget(self.continue_button)

        self.Login_button = Button(
            text="Login existing account",
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.15},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.Login_button.bind(on_press=self.Login_account)
        self.add_widget(self.Login_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def continue_signup(self, instance):
        email_employer = self.email_input.text
        password_employer = self.password_input.text

        encrypted_employer_email = employer_cipher_suite.encrypt(
            email_employer.encode('utf-8'))
        encrypted_employer_password = employer_cipher_suite.encrypt(
            password_employer.encode('utf-8'))
        
        # create an employer object to be inserted into mongodb
        employer = {
            "email":base64.b64encode(encrypted_employer_email).decode('utf-8'),
            "password":base64.b64encode(encrypted_employer_password).decode('utf-8')
        }

        employer_collection.insert_one(employer)

        if email_employer == '' or password_employer == '':
            self.error_label.text = 'Please enter email and password.'
        else:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email_employer):
                # Create a file and write the email and password to it
                with open('employer_credentials.txt', 'a') as file:
                    file.write(
                        f"Encrypted Employer Email: {base64.b64encode(encrypted_employer_email).decode('utf-8')}\n")
                    file.write(
                        f"Encrypted Employer Password: {base64.b64encode(encrypted_employer_password).decode('utf-8')}\n\n")
                screen_manager.current = 'moreinfo2'
            else:
                self.error_label.text = 'Please enter a valid email.'

    def Login_account(self, instance):
        screen_manager.current = 'login1'

class AImatchingSystemScreen(Screen):
    pdf_path = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(AImatchingSystemScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        self.AI_label = Label(
            text='AI Resume Matching System',
            font_size=70,
            size_hint=(0.8, 0.2),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            font_name='SuperMario256',
            color = (0,0,0,1),
        )
        self.add_widget(self.AI_label)

        self.jobtitle_input = TextInput(
            hint_text='Job Title or Keyword',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.7},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
        )
        self.add_widget(self.jobtitle_input)

        self.location_input = TextInput(
            hint_text='City/Town, Country or Post Code',
            size_hint=(0.65, 0.08),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
        )
        self.add_widget(self.location_input)

        self.upload_button = Button(
            text='Upload PDF',
            size_hint=(0.65, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.45},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.upload_button.bind(on_press=self.show_file_chooser)
        self.add_widget(self.upload_button)

        self.file_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(0, 0, 0, 1),  # Set the color to black
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.37},
            font_name='Arial',
        )
        self.add_widget(self.file_label)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.3},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.continue_button = Button(
            text="Continue",
            font_size=20,
            size_hint=(0.2, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.2},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.continue_button.bind(on_press=self.continue_signup)
        self.add_widget(self.continue_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def show_file_chooser(self, instance):
        content = BoxLayout(orientation='vertical')
        file_chooser = FileChooserIconView()
        file_chooser.path = os.getcwd()
        content.add_widget(file_chooser)
        popup = Popup(title='Select a PDF file', content=content, size_hint=(0.8, 0.8))
        upload_button = Button(text='Upload', size_hint=(0.2, 0.1), font_name='Glossy Sheen Shine DEMO',)
        upload_button.bind(on_press=lambda x: self.upload_pdf(file_chooser.path, file_chooser.selection))
        content.add_widget(upload_button)
        upload_button.bind(on_press=popup.dismiss)
        close_button = Button(text='Close', size_hint=(0.2, 0.1),font_name='Glossy Sheen Shine DEMO',)
        close_button.bind(on_press=popup.dismiss)
        content.add_widget(close_button)
        popup.open()

    def upload_pdf(self, path, filename):
        if filename:
            pdf_path = filename[0]
            self.file_label.text = f"Selected PDF: {pdf_path}"
        else:
            self.error_label.text = "No PDF selected"

    def continue_signup(self, instance):
        job_title = self.jobtitle_input.text
        location = self.location_input.text
        filepath = self.file_label.text
        if job_title == '' or location == '' or filepath == "":
            self.error_label.text = 'Please enter Job Title, Location and upload your Resume.'
        else:
            screen_manager.current = 'homepage1'
            self.jobtitle_input.text = ""
            self.location_input.text = ""
            self.file_label.text = ""
            self.error_label.text = ""

class CompanyDetailsScreen(Screen):
    def __init__(self, **kwargs):
        super(CompanyDetailsScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        self.company_label = Label(
            text='Enter Company Details',
            font_size=70,
            size_hint=(0.8, 0.2),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            font_name='Dacherry',
            color = (0,0,0,1),
        )
        self.add_widget(self.company_label)

        self.company_name_input = TextInput(
            hint_text='Company Name',
            size_hint=(0.75, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.8},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
        )
        self.add_widget(self.company_name_input)

        self.location_input = TextInput(
            hint_text='Location',
            size_hint=(0.75, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.7},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
        )
        self.add_widget(self.location_input)

        self.size_input = TextInput(
            hint_text='Size of Company',
            size_hint=(0.75, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.6},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
        )
        self.add_widget(self.size_input)

        self.description_input = TextInput(
            hint_text='Company Description',
            size_hint=(0.75, 0.3),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            multiline=True,
        )
        self.add_widget(self.description_input)

        self.error_label = Label(
            text='',
            size_hint=(0.8, None),
            height=dp(60),
            color=(1, 0, 0, 1),  # Set the color to red
            halign='center',
            pos_hint={'center_x': 0.5, 'center_y': 0.2},
            font_name='Arial',
        )
        self.add_widget(self.error_label)

        self.submit_button = Button(
            text='Submit',
            size_hint=(0.3, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.1},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.submit_button.bind(on_press=self.submit_company_details)
        self.add_widget(self.submit_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def submit_company_details(self, instance):
        company_name = self.company_name_input.text
        location = self.location_input.text
        size = self.size_input.text
        description = self.description_input.text

        if company_name == "" or location == "" or size == "" or description == "":
            self.error_label.text = 'Please fill in all the details.'
        else:
            # Do something with the entered details, e.g. save to database or display a message
            print(f'Company Name: {company_name}\nLocation: {location}\nSize: {size}\nDescription: {description}')
            screen_manager.current = 'homepage2'


class JobseekerHomePage(Screen):
    def __init__(self, **kwargs):
        super(JobseekerHomePage, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        bg_image = Image(
            source='pic1.jpeg',
            size_hint=(1, 10),
            pos_hint={'center_x': 0.5, 'center_y': 1}
        )
        self.add_widget(bg_image)

        # Add the HireHive title label
        self.title_label = Label(
            text='Hire Hive',
            font_size=80,
            size_hint=(1, 0.2),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            font_name='SuperMario256',
            color = (1,1,1,1),
        )
        self.add_widget(self.title_label)

        # Add the search bar
        self.search_button = Button(
            text='Search for a job',
            size_hint=(0.8, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.75},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.search_button)

        # Add the suggested job list
        self.suggested_jobs_label = Label(
            text='Suggested Jobs',
            font_size=80,
            size_hint=(0.8, 0.1),
            pos_hint={'center_x': 0.2, 'center_y': 0.6},
            font_name='Glossy Sheen Shine DEMO',
            color = (0,0,0,1),
        )
        self.add_widget(self.suggested_jobs_label)

        #Suggested job list
        self.job_list_layout = GridLayout(cols=1, spacing=10, size_hint_y=None)
        self.job_list_layout.bind(minimum_height=self.job_list_layout.setter('height'))

        # Create some example suggested jobs
        for i in range(10):
            job_label = Button(
                text=f'Job {i}',
                size_hint=(1, None),
                height=40,
                font_name='Arial',
            )
            self.job_list_layout.add_widget(job_label)

        self.job_scrollview = ScrollView(
            size_hint=(1, 0.4),
            pos_hint={'center_x': 0.5, 'center_y': 0.35},
        )
        self.job_scrollview.add_widget(self.job_list_layout)
        self.add_widget(self.job_scrollview)

        # Add the home, saved, chatbot, notification, and me buttons
        self.home_button = Button(
            text='Home',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.1, 'center_y': 0.07},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.home_button)

        self.saved_button = Button(
            text='Saved',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.3, 'center_y': 0.07},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.search_button.bind(on_press=self.search)
        self.add_widget(self.saved_button)

        self.chatbot_button = Button(
            text='Chatbot',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.07},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.chatbot_button.bind(on_press=self.chatbot)
        self.add_widget(self.chatbot_button)

        self.notification_button = Button(
            text='Notifications',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.7, 'center_y': 0.07},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.notification_button.bind(on_press=self.notification)
        self.add_widget(self.notification_button)

        self.me_button = Button(
            text='Me',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.9, 'center_y': 0.07},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.me_button.bind(on_press=self.me)
        self.add_widget(self.me_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def chatbot(self, instance):
        screen_manager.current = 'chatbot1'

    def search(self, instance):
        screen_manager.current = 'search'

    def me(self,instance):
        screen_manager.current= 'profile1'

    def notification(self,instance):
        screen_manager.current = 'noti1'


class EmployerHomePage(Screen):
    def __init__(self, **kwargs):
        super(EmployerHomePage, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        self.layout = GridLayout(cols=1, size_hint_y=None, spacing=10)
        self.layout.bind(minimum_height=self.layout.setter('height'))

        bg_image = Image(
            source='pic1.jpeg',
            size_hint=(1, 10),
            pos_hint={'center_x': 0.5, 'center_y': 1}
        )
        self.add_widget(bg_image)

        # HireHive title
        self.title_label = Label(
            text='HireHive',
            font_size=100,
            size_hint=(1, 0.2),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            font_name='Dacherry',
            color = (1,1,1,1),
        )
        self.add_widget(self.title_label)

        self.posted_jobs_label = Label(
            text='Posted Jobs',
            font_size=80,
            size_hint=(0.8, 0.1),
            pos_hint={'center_x': 0.2, 'center_y': 0.6},
            color = (0,0,0,1),
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.posted_jobs_label)

        # Posted job list
        self.job_list_layout = GridLayout(cols=1, spacing=10, size_hint_y=None)
        self.job_list_layout.bind(minimum_height=self.job_list_layout.setter('height'))

        # Create some example posted jobs
        for i in range(10):
            job_label = Button(
                text=f'Job {i}',
                size_hint=(1, None),
                height=40,
                color = (0,0,0,1),
                font_name='Arial',
            )
            self.job_list_layout.add_widget(job_label)

        self.job_scrollview = ScrollView(
            size_hint=(1, 0.4),
            pos_hint={'center_x': 0.5, 'center_y': 0.35},
        )
        self.job_scrollview.add_widget(self.job_list_layout)
        self.add_widget(self.job_scrollview)

        # Navigation buttons
        self.navigation_layout = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.05},
        )

        # Home button
        self.home_button = Button(
            text='Home',
            size_hint=(0.2, 1),
            pos_hint={'center_x': 0.1, 'center_y': 0.5},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.navigation_layout.add_widget(self.home_button)

        # Saved button
        self.saved_button = Button(
            text='Saved',
            size_hint=(0.2, 1),
            pos_hint={'center_x': 0.3, 'center_y': 0.5},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.navigation_layout.add_widget(self.saved_button)

        # Post button
        self.post_button = Button(
            text='Post Job',
            size_hint=(0.2, 1),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.navigation_layout.add_widget(self.post_button)
        self.post_button.bind(on_press=self.post_job)


        # Notification button
        self.notification_button = Button(
            text='Notifications',
            size_hint=(0.2, 1),
            pos_hint={'center_x': 0.7, 'center_y': 0.5},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.navigation_layout.add_widget(self.notification_button)

        # Me button
        self.me_button = Button(
            text='Me',
            size_hint=(0.2, 1),
            pos_hint={'center_x': 0.9, 'center_y': 0.5},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.me_button.bind(on_press=self.me)
        self.navigation_layout.add_widget(self.me_button)

        # Chatbot button
        self.chatbot_button = Button(
            text='Chatbot',
            size_hint=(0.1, 0.1),
            pos_hint={'right': 1, 'center_y': 0.25},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.chatbot_button)

        self.add_widget(self.navigation_layout)

    def on_size(self, *args):
        self.rect.size = self.size

    def me(self,instance):
        screen_manager.current= 'profile2'

    def post_job(self,instance):
        screen_manager.current='postjob'

class JobPostingScreen(Screen):
    def __init__(self, **kwargs):
        super(JobPostingScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        self.text_color = (0, 0, 0, 1)

        self.title_label = Label(
            text='Post a Job',
            color=self.text_color,
            font_size=30,
            pos=(Window.width/2, Window.height - 100),
            size_hint=(None, None),
            size=(300, 50),
            halign='center',
            valign='middle',
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.title_label)

        self.job_title_label = Label(
            text='Job Title:',
            color=self.text_color,
            font_size=20,
            pos=(50, Window.height - 200),
            size_hint=(None, None),
            size=(150, 30),
            halign='left',
            valign='middle',
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.job_title_label)

        self.job_title_input = TextInput(
            hint_text='Enter job title',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            font_size=16,
            pos=(200, Window.height - 200),
            size_hint=(None, None),
            size=(300, 30)
        )
        self.add_widget(self.job_title_input)

        self.location_label = Label(
            text='Location:',
            color=self.text_color,
            font_name='Arial',
            font_size=20,
            pos=(50, Window.height - 300),
            size_hint=(None, None),
            size=(150, 30),
            halign='left',
            valign='middle'
        )
        self.add_widget(self.location_label)

        self.location_input = TextInput(
            hint_text='Enter location',
            font_name='Arial',
            font_size=16,
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            pos=(200, Window.height - 300),
            size_hint=(None, None),
            size=(300, 30)
        )
        self.add_widget(self.location_input)

        self.job_type_label = Label(
            text='Job Type:',
            font_name='Arial',
            color=self.text_color,
            font_size=20,
            pos=(50, Window.height - 400),
            size_hint=(None, None),
            size=(150, 30),
            halign='left',
            valign='middle'
        )
        self.add_widget(self.job_type_label)

        self.job_type_input = TextInput(
            hint_text='Enter job type',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            font_size=16,
            pos=(200, Window.height - 400),
            size_hint=(None, None),
            size=(300, 30)
        )
        self.add_widget(self.job_type_input)

        self.num_employees_label = Label(
            text='Number of Employees:',
            font_name='Arial',
            color=self.text_color,
            font_size=20,
            pos=(50, Window.height - 500),
            size_hint=(None, None),
            size=(250, 30),
            halign='left',
            valign='middle'
        )
        self.add_widget(self.num_employees_label)

        self.num_employees_input = TextInput(
            hint_text='Enter number of employees',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            font_size=16,
            pos=(300, Window.height - 500),
            size_hint=(None, None),
            size=(200, 30)
        )
        self.add_widget(self.num_employees_input)

        self.salary_label = Label(
            text='Salary:',
            color=self.text_color,
            font_name='Arial',
            font_size=20,
            pos=(50, Window.height - 600),
            size_hint=(None, None),
            size=(150, 30),
            halign='left',
            valign='middle'
        )
        self.add_widget(self.salary_label)

        self.salary_input = TextInput(
            hint_text='Enter salary',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            font_size=16,
            pos=(200, Window.height - 600),
            size_hint=(None, None),
            size=(300, 30)
        )
        self.add_widget(self.salary_input)

        self.job_desc_label = Label(
            text='Job Description:',
            color=self.text_color,
            font_name='Arial',
            font_size=20,
            pos=(50, Window.height - 700),
            size_hint=(None, None),
            size=(200, 30),
            halign='left',
            valign='middle'
        )
        self.add_widget(self.job_desc_label)

        self.job_desc_input = TextInput(
            hint_text='Enter job description',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            font_size=16,
            pos=(250, Window.height - 700),
            size_hint=(None, None),
            size=(250, 100)
        )
        self.add_widget(self.job_desc_input)

        self.post_button = Button(
            text='Post',
            font_name='Arial',
            pos=(Window.width/2 - 50, 50),
            size_hint=(None, None),
            size=(100, 40),
        )
        self.add_widget(self.post_button)
        self.post_button.bind(on_press=self.post_job)

    def on_size(self, *args):
        self.rect.size = self.size

    def post_job(self, instance):
        job_title = self.job_title_input.text
        location = self.location_input.text
        job_type = self.job_type_input.text
        num_employees = self.num_employees_input.text
        salary = self.salary_input.text
        job_description = self.job_desc_input.text

        # Do something with the job details (e.g., save to a database, display a confirmation message, etc.)
        print(job_title, location, job_type,num_employees,salary,job_description)
        screen_manager.current = 'homepage2'
        # Clear the input fields
        self.job_title_input.text = ''
        self.location_input.text = ''
        self.job_type_input.text = ''
        self.num_employees_input.text = ''
        self.salary_input.text = ''
        self.job_desc_input.text = ''

        # Optionally, navigate to a different screen after posting the job





class ChatBotScreen(Screen):
    def __init__(self, **kwargs):
        super(ChatBotScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.orientation = 'vertical'

        self.history_label = Label(
            text="Welcome to the chatbot! Type something to get started.",
            size_hint=(1, 0.8),
            font_name='Arial',
            text_size=(Window.width - 50, None),
            halign='center',
            valign='top',
            padding=(25, 25),
            color = (0,0,0,1),
        )

        self.add_widget(self.history_label)

        self.input_layout = BoxLayout(
            size_hint=(1, 0.1),
            padding=(25, 10),
        )

        self.input_text = TextInput(
            multiline=False,
            size_hint=(0.8, 1),
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            hint_text="Type here",
        )

        self.send_button = Button(
            text="Send",
            size_hint=(0.2, 1),
            color=(1, 1, 1, 1),
            font_name='Glossy Sheen Shine DEMO',
        )
        self.send_button.bind(on_press=self.send_message)

        self.input_layout.add_widget(self.input_text)
        self.input_layout.add_widget(self.send_button)

        self.add_widget(self.input_layout)

        # Create a button to return to the homepage
        self.return_button = Button(
            text='Return to Homepage',
            font_name='Glossy Sheen Shine DEMO',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.15, 'center_y': 0.9},
        )
        self.return_button.bind(on_press=self.return_homepage)
        self.add_widget(self.return_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def send_message(self, instance):
        message = self.input_text.text
        self.input_text.text = ""

        response = self.get_response(message)

        self.history_label.text += "\n\nUser: {}\nChatbot: {}".format(message, response)

    def get_response(self, message):
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=message,
            max_tokens=20,
            temperature=0
        )
        # Insert your chatbot logic here
        return response.choices[0].text.strip()

    def return_homepage(self, instance):
        # Get the parent ScreenManager and switch to the homepage screen
        sm = self.parent
        sm.current = 'homepage1'

class SearchPage(Screen):
    def __init__(self, **kwargs):
        super(SearchPage, self).__init__(**kwargs)
        with self.canvas:
            Color(238 / 255, 233 / 255, 218 / 255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.cols = 2

        # Create a button to return to homepage
        self.home_button = Button(
            text='Return to homepage',
            size_hint=(0.2, 0.1),
            pos_hint={'x': 0.025, 'y': 0.85},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.home_button.bind(on_press=self.return_homepage)
        self.add_widget(self.home_button)

        # Create a text input widget for the job title
        self.job_title_input = TextInput(
            hint_text='Enter job title',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            size_hint=(0.8, 0.1),
            pos_hint={'x': 0.1, 'y': 0.75},
        )
        self.add_widget(self.job_title_input)

        # Create a text input widget for the location
        self.location_input = TextInput(
            hint_text='Enter location',
            font_name='Arial',
            background_color=(217 / 255, 217 / 255, 217 / 255, 1),
            background_active="",
            background_normal="",
            size_hint=(0.8, 0.1),
            pos_hint={'x': 0.1, 'y': 0.65},
        )
        self.add_widget(self.location_input)

        # Create the search button
        self.search_button = Button(
            text='Search',
            font_name='Glossy Sheen Shine DEMO',
            size_hint=(0.4, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.4},
        )
        self.search_button.bind(on_press=self.search)
        self.add_widget(self.search_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def return_homepage(self, instance):
        screen_manager.current = 'homepage1'

    def search(self, instance):
        job_title = self.job_title_input.text
        location = self.location_input.text
        print(f'Searching for jobs with title "{job_title}" in location "{location}"...')

class ProfilePage(Screen):
    def __init__(self, **kwargs):
        super(ProfilePage, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        # Create a label for the page title
        self.title_label = Label(
            text='Profile Page',
            font_size=30,
            size_hint=(1, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            color=(0, 0, 0, 1),
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.title_label)

        self.return_button = Button(
            text='Return to Homepage',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.15, 'center_y': 0.9},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.return_button.bind(on_press=self.return_homepage)
        self.add_widget(self.return_button)

        # Create a button for system settings
        self.settings_button = Button(
            text='System Settings',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.75},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.settings_button)

        # Create a dropdown button for language selection
        self.languages_button = Button(
            text='Select Language',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.65},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.languages_dropdown = DropDown()
        self.languages = ['English']
        for language in self.languages:
            btn = Button(text=language, size_hint_y=None, height=30)
            btn.bind(on_release=lambda btn: self.languages_dropdown.select(btn.text))
            self.languages_dropdown.add_widget(btn)
        self.languages_button.bind(on_release=self.languages_dropdown.open)
        self.languages_dropdown.bind(on_select=lambda instance, x: setattr(self.languages_button, 'text', x))
        self.add_widget(self.languages_button)

        # Create a button for profile preferences
        self.preferences_button = Button(
            text='Profile Preferences',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.55},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.preferences_button)

        self.upload_button = Button(
            text='Upload PDF',
            size_hint=(0.3, 0.07),
            pos_hint={'center_x': 0.5, 'center_y': 0.45},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.upload_button.bind(on_press=self.show_file_chooser)
        self.add_widget(self.upload_button)

        # Create a button for sign out
        self.signout_button = Button(
            text='Sign Out',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.2},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.signout_button.bind(on_press=self.sign_out)
        self.add_widget(self.signout_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def return_homepage(self, instance):
        # Get the parent ScreenManager and switch to the homepage screen
        sm = self.parent
        sm.current = 'homepage1'

    def sign_out(self,instance):
        screen_manager.current = 'login1'

    def show_file_chooser(self, instance):
        content = BoxLayout(orientation='vertical')
        file_chooser = FileChooserIconView()
        file_chooser.path = os.getcwd()
        content.add_widget(file_chooser)
        popup = Popup(title='Select a PDF file', content=content, size_hint=(0.8, 0.8))
        upload_button = Button(text='Upload', font_name='Glossy Sheen Shine DEMO',size_hint=(0.2, 0.1))
        upload_button.bind(on_press=lambda x: self.upload_pdf(file_chooser.path, file_chooser.selection))
        content.add_widget(upload_button)
        close_button = Button(text='Close', font_name='Glossy Sheen Shine DEMO', size_hint=(0.2, 0.1))
        close_button.bind(on_press=popup.dismiss)
        content.add_widget(close_button)
        popup.open()

    def upload_pdf(self, path, filename):
        if filename:
            pdf_path = os.path.join(path, filename[0])
            print(f"Selected PDF: {pdf_path}")
        else:
            print("No PDF selected")

class ComapanyProfilePage(Screen):
    def __init__(self, **kwargs):
        super(ComapanyProfilePage, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        # Create a label for the page title
        self.title_label = Label(
            text='Company Profile Page',
            font_name='Glossy Sheen Shine DEMO',
            font_size=30,
            size_hint=(1, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            color = (0,0,0,1),
        )
        self.add_widget(self.title_label)

        self.return_button = Button(
            text='Return to Homepage',
            font_name='Glossy Sheen Shine DEMO',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.15, 'center_y': 0.9},
        )
        self.return_button.bind(on_press=self.return_homepage)
        self.add_widget(self.return_button)

        # Create a button for system settings
        self.settings_button = Button(
            text='System Settings',
            font_name='Glossy Sheen Shine DEMO',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.75},
        )
        self.add_widget(self.settings_button)

        # Create a dropdown button for language selection
        self.languages_button = Button(
            text='Select Language',
            font_name='Glossy Sheen Shine DEMO',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.65},
        )
        self.languages_dropdown = DropDown()
        self.languages = ['English']
        for language in self.languages:
            btn = Button(text=language, size_hint_y=None, font_name='Arial', height=30)
            btn.bind(on_release=lambda btn: self.languages_dropdown.select(btn.text))
            self.languages_dropdown.add_widget(btn)
        self.languages_button.bind(on_release=self.languages_dropdown.open)
        self.languages_dropdown.bind(on_select=lambda instance, x: setattr(self.languages_button, 'text', x))
        self.add_widget(self.languages_button)

        # Create a button for profile preferences
        self.preferences_button = Button(
            text='Profile Preferences',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.55},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.add_widget(self.preferences_button)

        # Create a button for sign out
        self.signout_button = Button(
            text='Sign Out',
            size_hint=(0.3, 0.05),
            pos_hint={'center_x': 0.5, 'center_y': 0.2},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.signout_button.bind(on_press=self.sign_out)
        self.add_widget(self.signout_button)

    def on_size(self, *args):
        self.rect.size = self.size

    def return_homepage(self, instance):
        # Get the parent ScreenManager and switch to the homepage screen
        sm = self.parent
        sm.current = 'homepage2'

    def sign_out(self,instance):
        screen_manager.current = 'login2'

class NotificationScreen(Screen):
    def __init__(self, num=None, **kwargs):
        super(NotificationScreen, self).__init__(**kwargs)
        with self.canvas:
            Color(238/255, 233/255, 218/255)  # Set the background color
            self.rect = Rectangle(pos=self.pos, size=self.size)

        # Add a return to homepage button on the top left
        self.return_button = Button(
            text='Return to Homepage',
            size_hint=(0.2, 0.1),
            pos_hint={'center_x': 0.15, 'center_y': 0.9},
            font_name='Glossy Sheen Shine DEMO',
        )
        self.return_button.bind(on_press=self.go_to_homepage)
        self.add_widget(self.return_button)

        # Add a label for the screen title
        self.title_label = Label(
            text="Notifications",
            font_size=50,
            size_hint=(0.5, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 0.9},
            font_name='Glossy Sheen Shine DEMO',
            color = (0,0,0,1),
        )
        self.add_widget(self.title_label)

        # Add some example notifications
        self.notifications = [
            {'message': 'Your job posting for a software engineer has been approved.', 'date': 'May 1, 2023'},
            {'message': 'Your job posting for a marketing coordinator has expired.', 'date': 'May 3, 2023'},
            {'message': 'You have a new message from a candidate for the position of accountant.',
             'date': 'May 5, 2023'},
        ]
        self.notification_labels = []

        for i, notification in enumerate(self.notifications):
            outline = "-" * 150
            label_text = f'{notification["date"]} - {notification["message"]} ' \
                         f'\n{outline}'

            label = Label(
                text=label_text,
                size_hint=(0.8, None),
                height=40,
                font_name='Arial',
                pos_hint={'center_x': 0.5, 'center_y': 0.7 - i * 0.1},
                color = (0,0,0,1),
            )
            self.add_widget(label)
            self.notification_labels.append(label)

    def on_size(self, *args):
        self.rect.size = self.size

    def go_to_homepage(self, instance):
        self.manager.current = "homepage1"


class MyScreenManager(ScreenManager):
    pass

class MyApp(App):
    def build(self):
        # Create the screen manager
        global screen_manager
        screen_manager = MyScreenManager()

        screen_manager.add_widget(EmployeeLoginScreen(name='login1'))
        screen_manager.add_widget(EmployerLoginScreen(name='login2'))
        screen_manager.add_widget(SignupJobSeekerScreen(name='signup1'))
        screen_manager.add_widget(SignupEmployerScreen(name='signup2'))
        screen_manager.add_widget(AImatchingSystemScreen(name='moreinfo1'))
        screen_manager.add_widget(CompanyDetailsScreen(name='moreinfo2'))
        screen_manager.add_widget(JobseekerHomePage(name='homepage1'))
        screen_manager.add_widget(EmployerHomePage(name='homepage2'))
        screen_manager.add_widget(ChatBotScreen(name='chatbot1'))
        screen_manager.add_widget(SearchPage(name='search'))
        screen_manager.add_widget(ProfilePage(name='profile1'))
        screen_manager.add_widget(ComapanyProfilePage(name='profile2'))
        screen_manager.add_widget(NotificationScreen(name='noti1'))
        screen_manager.add_widget(JobPostingScreen(name='postjob'))

        return screen_manager


if __name__ == '__main__':
    MyApp().run()

