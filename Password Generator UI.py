import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import os
import datetime  # Add this import

class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("500x600")
        self.root.configure(bg="#f0f0f0")
        
        # Create main frame
        main_frame = tk.Frame(root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text="🔐 Password Generator", 
            font=("Arial", 24, "bold"),
            bg="#f0f0f0",
            fg="#2c3e50"
        )
        title_label.pack(pady=(0, 20))
        
        # Password length frame
        length_frame = tk.Frame(main_frame, bg="#f0f0f0")
        length_frame.pack(fill="x", pady=10)
        
        tk.Label(
            length_frame, 
            text="Password Length:", 
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(side="left")
        
        self.length_var = tk.StringVar(value="12")
        length_spinbox = tk.Spinbox(
            length_frame, 
            from_=8, 
            to=20, 
            textvariable=self.length_var,
            width=10,
            font=("Arial", 11)
        )
        length_spinbox.pack(side="right")
        
        # Character options frame
        options_frame = tk.LabelFrame(
            main_frame, 
            text="Character Options", 
            font=("Arial", 12, "bold"),
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        options_frame.pack(fill="x", pady=20)
        
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        
        tk.Checkbutton(
            options_frame, 
            text="Uppercase Letters (A-Z)", 
            variable=self.include_uppercase,
            font=("Arial", 10, "bold"),
            bg="#f0f0f0"
        ).pack(anchor="w")
        
        tk.Checkbutton(
            options_frame, 
            text="Lowercase Letters (a-z)", 
            variable=self.include_lowercase,
            font=("Arial", 10, "bold"),
            bg="#f0f0f0"
        ).pack(anchor="w")
        
        tk.Checkbutton(
            options_frame, 
            text="Numbers (0-9)", 
            variable=self.include_numbers,
            font=("Arial", 10, "bold"),
            bg="#f0f0f0"
        ).pack(anchor="w")
        
        tk.Checkbutton(
            options_frame, 
            text="Special Characters (!@#$%^&*)", 
            variable=self.include_symbols,
            font=("Arial", 10, "bold"),
            bg="#f0f0f0"
        ).pack(anchor="w")
        
        # Generate button
        generate_btn = tk.Button(
            main_frame,
            text="🎲 Generate Password",
            command=self.generate_password,
            font=("Arial", 14, "bold"),
            bg="#3498db",
            fg="white",
            pady=10,
            cursor="hand2"
        )
        generate_btn.pack(fill="x", pady=20)
        
        # Password display frame
        display_frame = tk.LabelFrame(
            main_frame, 
            text="Generated Password", 
            font=("Arial", 12, "bold"),
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        display_frame.pack(fill="x", pady=10)
        
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(
            display_frame,
            textvariable=self.password_var,
            font=("Courier", 14),
            justify="center",
            state="readonly",
            readonlybackground="white"
        )
        password_entry.pack(fill="x", pady=5)
        
        # Button frame
        button_frame = tk.Frame(display_frame, bg="#f0f0f0")
        button_frame.pack(fill="x", pady=5)
        
        copy_btn = tk.Button(
            button_frame,
            text="📋 Copy",
            command=self.copy_password,
            font=("Arial", 10),
            bg="#27ae60",
            fg="white",
            cursor="hand2"
        )
        copy_btn.pack(side="left", padx=(0, 5))
        
        save_btn = tk.Button(
            button_frame,
            text="💾 Save to File",
            command=self.save_password,
            font=("Arial", 10),
            bg="#e67e22",
            fg="white",
            cursor="hand2"
        )
        save_btn.pack(side="left")
        
        # Password strength indicator
        self.strength_var = tk.StringVar()
        strength_label = tk.Label(
            main_frame,
            textvariable=self.strength_var,
            font=("Arial", 11, "bold"),
            bg="#f0f0f0"
        )
        strength_label.pack(pady=10)
        
        # Security tips
        tips_frame = tk.LabelFrame(
            main_frame,
            text="Security Tips",
            font=("Arial", 10, "bold"),
            bg="#f0f0f0"
        )
        tips_frame.pack(fill="x", pady=10)
        
        tips_text = tk.Text(
            tips_frame,
            height=4,
            font=("Arial", 9),
            wrap="word",
            bg="#f8f9fa",
            state="disabled"
        )
        tips_text.pack(fill="x", padx=5, pady=5)
        
        # Insert tips
        tips_content = """• Use different passwords for different accounts
• Store passwords securely using a password manager
• Enable two-factor authentication when available
• Avoid using personal information in passwords"""
        
        tips_text.config(state="normal")
        tips_text.insert("1.0", tips_content)
        tips_text.config(state="disabled")
    
    def generate_password(self):
        try:
            length = int(self.length_var.get())
            
            if not (8 <= length <= 20):
                messagebox.showerror("Error", "Password length must be between 8 and 20 characters!")
                return
            
            # Build character set based on selections
            characters = ""
            if self.include_lowercase.get():
                characters += "abcdefghijklmnopqrstuvwxyz"
            if self.include_uppercase.get():
                characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if self.include_numbers.get():
                characters += "0123456789"
            if self.include_symbols.get():
                characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not characters:
                messagebox.showerror("Error", "Please select at least one character type!")
                return
            
            # Generate password
            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_var.set(password)
            
            # Update strength indicator
            self.update_strength_indicator(password)
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length!")
    
    def update_strength_indicator(self, password):
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score <= 2:
            strength = "Weak 🔴"
            color = "#e74c3c"
        elif score <= 3:
            strength = "Medium 🟡"
            color = "#f39c12"
        elif score <= 4:
            strength = "Strong 🟢"
            color = "#27ae60"
        else:
            strength = "Very Strong 🟢"
            color = "#27ae60"
        
        self.strength_var.set(f"Password Strength: {strength}")
        # Update label color (you'd need to store reference to update fg)
    
    def copy_password(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy!")
    
    def save_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password to save!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialname="generated_password.txt"
        )
        
        if file_path:
            try:
                with open(file_path, "w") as file:
                    file.write(f"Generated Password: {password}\n")
                    file.write(f"Length: {len(password)} characters\n")
                    file.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                messagebox.showinfo("Success", f"Password saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save password:\n{str(e)}")

def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()