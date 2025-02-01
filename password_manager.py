from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

# Generate or load a key for encryption
def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return key

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Save password to a file
def save_password(service, username, password, key):
    encrypted_username = encrypt_data(username, key)
    encrypted_password = encrypt_data(password, key)
    with open("passwords.txt", "a") as file:
        file.write(f"{service}:{encrypted_username.decode()}:{encrypted_password.decode()}\n")

# Retrieve all passwords
def get_all_passwords(key):
    if not os.path.exists("passwords.txt"):
        return []
    passwords = []
    with open("passwords.txt", "r") as file:
        for line in file:
            parts = line.strip().split(":")
            service = parts[0]
            username = decrypt_data(parts[1].encode(), key)
            password = decrypt_data(parts[2].encode(), key)
            passwords.append((service, username, password))
    return passwords

# Delete password for a service
def delete_password(service, key):
    if not os.path.exists("passwords.txt"):
        return False
    with open("passwords.txt", "r") as file:
        lines = file.readlines()
    with open("passwords.txt", "w") as file:
        deleted = False
        for line in lines:
            parts = line.strip().split(":")
            if parts[0] != service:
                file.write(line)
            else:
                deleted = True
        return deleted

# GUI Application
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x400")  # Larger window size
        self.key = load_key()

        # Create GUI elements
        self.label = tk.Label(root, text="Password Manager", font=("Arial", 16))
        self.label.pack(pady=10)

        # Frame for the password list
        self.list_frame = tk.Frame(root)
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Listbox to display services
        self.service_listbox = tk.Listbox(self.list_frame, width=50, height=15)
        self.service_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for the listbox
        self.scrollbar = tk.Scrollbar(self.list_frame, orient=tk.VERTICAL)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.service_listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.service_listbox.yview)

        # Bind double-click event to show password
        self.service_listbox.bind("<Double-Button-1>", self.show_password)

        # Buttons
        self.add_button = tk.Button(root, text="Add Password", command=self.add_password)
        self.add_button.pack(pady=5)

        self.delete_button = tk.Button(root, text="Delete Password", command=self.delete_password)
        self.delete_button.pack(pady=5)

        # Load and display passwords
        self.refresh_password_list()

    def refresh_password_list(self):
        """Refresh the list of passwords displayed in the Listbox."""
        self.service_listbox.delete(0, tk.END)
        passwords = get_all_passwords(self.key)
        for service, username, _ in passwords:
            self.service_listbox.insert(tk.END, f"Service: {service} | Username: {username}")

    def add_password(self):
        """Add a new password."""
        service = simpledialog.askstring("Add Password", "Enter the service name:")
        if service:
            username = simpledialog.askstring("Add Password", "Enter the username:")
            if username:
                password = simpledialog.askstring("Add Password", "Enter the password:")
                if password:
                    save_password(service, username, password, self.key)
                    messagebox.showinfo("Success", "Password saved successfully!")
                    self.refresh_password_list()

    def delete_password(self):
        """Delete a password with confirmation."""
        selected = self.service_listbox.curselection()
        if not selected:
            messagebox.showinfo("Error", "Please select a service to delete.")
            return

        # Get the selected service
        selected_service = self.service_listbox.get(selected).split(" | ")[0].replace("Service: ", "")

        # Ask for confirmation
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete the password for '{selected_service}'?"
        )

        # Proceed with deletion if confirmed
        if confirm:
            if delete_password(selected_service, self.key):
                messagebox.showinfo("Success", f"Password for {selected_service} deleted successfully!")
                self.refresh_password_list()
            else:
                messagebox.showinfo("Error", f"No password found for {selected_service}.")

    def show_password(self, event):
        """Show the password when a row is double-clicked."""
        selected = self.service_listbox.curselection()
        if not selected:
            return
        selected_service = self.service_listbox.get(selected).split(" | ")[0].replace("Service: ", "")
        passwords = get_all_passwords(self.key)
        for service, username, password in passwords:
            if service == selected_service:
                messagebox.showinfo("Password", f"Service: {service}\nUsername: {username}\nPassword: {password}")
                break

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()