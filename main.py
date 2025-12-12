#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
from datetime import datetime
import sqlite3
import sys


# =================== LOGIN WINDOW ======================
class LoginWindow:
    def __init__(self, parent_callback):
        
        self.parent_callback = parent_callback
        self.login_window = tk.Toplevel()
        # If icon file is missing, ignore error
        try:
            self.login_window.iconbitmap("nmap_icon.ico")
        except Exception:
            pass
        self.login_window.title("User Authentication")
        self.login_window.geometry("320x300")
        self.login_window.configure(bg="#f0f4f8")
        self.login_window.resizable(True, True)
        self.login_window.grab_set()

        self.default_users = {
            "admin": "1234"
        }

        self.create_login_widgets()

    def create_login_widgets(self):
        heading = tk.Label(self.login_window, text="🔐 Secure Login", font=("Segoe UI", 16, "bold"),
                           fg="#2E86AB", bg="#f0f4f8")
        heading.pack(pady=(20, 10))

        form_frame = tk.Frame(self.login_window, bg="#f0f4f8")
        form_frame.pack(padx=30, pady=10)

        tk.Label(form_frame, text="Username", font=("Segoe UI", 10), bg="#f0f4f8").pack(anchor="w")
        self.username_entry = tk.Entry(form_frame, width=30, font=("Segoe UI", 10))
        self.username_entry.pack(pady=5)

        tk.Label(form_frame, text="Password", font=("Segoe UI", 10), bg="#f0f4f8").pack(anchor="w")
        self.password_entry = tk.Entry(form_frame, show="*", width=30, font=("Segoe UI", 10))
        self.password_entry.pack(pady=5)

        button_frame = tk.Frame(form_frame, bg="#f0f4f8")
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Login", command=self.authenticate, bg="#2E86AB", fg="white",
                  font=("Segoe UI", 10, "bold"), width=10).pack(side="left", padx=5)

        tk.Button(button_frame, text="Register", command=self.register_user, bg="#28A745", fg="white",
                  font=("Segoe UI", 10), width=10).pack(side="left", padx=5)

        tk.Button(form_frame, text="Forgot Password?", command=self.forgot_password,
                  fg="#007BFF", bg="#f0f4f8", font=("Segoe UI", 9, "underline"), bd=0).pack()

        self.login_window.bind('<Return>', lambda event: self.authenticate())

    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password!")
            return

        if username in self.default_users and self.default_users[username] == password:
            self.login_window.destroy()
            self.parent_callback(username)
            return

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            result = cursor.fetchone()
            conn.close()
            if result:
                self.login_window.destroy()
                self.parent_callback(username)
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def register_user(self):
        username = simpledialog.askstring("Register", "Enter username:")
        if not username:
            return
        password = simpledialog.askstring("Register", "Enter password:", show="*")
        if not password:
            return
        email = simpledialog.askstring("Register", "Enter email:")
        if not email:
            return
        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                           (username, password, email))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Registration successful!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username or email already exists.")
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def forgot_password(self):
        email = simpledialog.askstring("Forgot Password", "Enter your username:")
        if not email:
            return
        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE email=?", (email,))
            result = cursor.fetchone()
            if result:
                new_password = simpledialog.askstring("Reset Password", "Enter new password:", show="*")
                if new_password:
                    cursor.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
                    conn.commit()
                    messagebox.showinfo("Success", "Password updated successfully!")
            else:
                messagebox.showerror("Not Found", "No user found with that email.")
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


# =================== MAIN NMAP GUI ======================
class NmapGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Nmap GUI - Made by Prasad")
        self.geometry("750x750")
        self.current_user = None
        self.logs_directory = "nmap_logs"

        if not os.path.exists(self.logs_directory):
            os.makedirs(self.logs_directory)

        self.withdraw()
        self.show_login()

    def show_login(self):
        LoginWindow(self.on_login_success)

    def on_login_success(self, username):
        self.current_user = username
        self.deiconify()
        self.show_greeting()
        self.create_widgets()
        self.create_status_bar()

    def show_greeting(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        greeting_msg = f"Welcome, {self.current_user}!\n\nLogin Time: {current_time}\nHappy Scanning! 🛡️"
        messagebox.showinfo("Welcome!", greeting_msg)

    def create_widgets(self):
        # Remove any existing widgets (if relogin)
        for widget in self.winfo_children():
            widget.destroy()

        user_frame = tk.Frame(self, bg="#2E86AB")
        user_frame.pack(fill="x")

        user_label = tk.Label(user_frame, text=f"Logged in as: {self.current_user}", fg="white", bg="#2E86AB", font=("Arial", 10))
        user_label.pack(side="left", padx=10, pady=5)

        logout_btn = tk.Button(user_frame, text="Logout", command=self.logout, bg="#A23B72", fg="white", font=("Arial", 8))
        logout_btn.pack(side="right", padx=10, pady=5)

        target_frame = tk.LabelFrame(self, text="Target Specification", padx=10, pady=10)
        target_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(target_frame, text="Target (hostname/IP):").grid(row=0, column=0, sticky="w")
        self.target_entry = tk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=2)

        #  Browse-enabled Input File
        tk.Label(target_frame, text="Input File (-iL):").grid(row=1, column=0, sticky="w")
        self.input_file_entry = tk.Entry(target_frame, width=40)
        self.input_file_entry.grid(row=1, column=1, padx=5, pady=2)

        browse_btn = tk.Button(target_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=1, column=2, padx=5, pady=2)

        host_frame = tk.LabelFrame(self, text="Host Discovery", padx=10, pady=10)
        host_frame.pack(fill="x", padx=10, pady=5)

        self.sn_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-sn (Ping Scan)", variable=self.sn_var).grid(row=0, column=0, sticky="w", padx=5)
        self.sL_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-sL (List Scan)", variable=self.sL_var).grid(row=0, column=1, sticky="w", padx=5)
        self.Pn_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-Pn (Treat all hosts as online)", variable=self.Pn_var).grid(row=0, column=2, sticky="w", padx=5)

        scan_frame = tk.LabelFrame(self, text="Scan Techniques", padx=10, pady=10)
        scan_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(scan_frame, text="Scan Type:").grid(row=0, column=0, sticky="w")
        scan_types = ["None","-sS (TCP SYN scan)", "-sT (TCP Connect scan)", "-sU (UDP scan)", "-sA (TCP ACK scan)"]
        self.scan_combo = ttk.Combobox(scan_frame, values=scan_types, state="readonly", width=30)
        self.scan_combo.current(0)
        self.scan_combo.grid(row=0, column=1, padx=5, pady=2)

        port_frame = tk.LabelFrame(self, text="Port Specification", padx=10, pady=10)
        port_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(port_frame, text="Ports (-p):").grid(row=0, column=0, sticky="w")
        self.port_entry = tk.Entry(port_frame, width=20)
        self.port_entry.grid(row=0, column=1, padx=5, pady=2)

        service_frame = tk.LabelFrame(self, text="Service/Version & OS Detection", padx=10, pady=10)
        service_frame.pack(fill="x", padx=10, pady=5)

        self.sV_var = tk.BooleanVar()
        tk.Checkbutton(service_frame, text="-sV (Service/Version detection)", variable=self.sV_var).grid(row=0, column=0, sticky="w", padx=5)
        self.O_var = tk.BooleanVar()
        tk.Checkbutton(service_frame, text="-O (OS detection)", variable=self.O_var).grid(row=0, column=1, sticky="w", padx=5)

        script_frame = tk.LabelFrame(self, text="Script Scan", padx=10, pady=10)
        script_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(script_frame, text="Scripts (--script):").grid(row=0, column=0, sticky="w")
        self.script_entry = tk.Entry(script_frame, width=40)
        self.script_entry.grid(row=0, column=1, padx=5, pady=2)

        misc_frame = tk.LabelFrame(self, text="Timing and Miscellaneous Options", padx=10, pady=10)
        misc_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(misc_frame, text="Timing Template (-T0 to -T5):").grid(row=0, column=0, sticky="w")
        self.timing_entry = tk.Entry(misc_frame, width=5)
        self.timing_entry.grid(row=0, column=1, padx=5, pady=2)

        self.ipv6_var = tk.BooleanVar()
        tk.Checkbutton(misc_frame, text="-6 (IPv6)", variable=self.ipv6_var).grid(row=0, column=2, sticky="w", padx=5)

        custom_frame = tk.LabelFrame(self, text="Additional Custom Options", padx=10, pady=10)
        custom_frame.pack(fill="x", padx=10, pady=5)

        self.custom_entry = tk.Entry(custom_frame, width=70)
        self.custom_entry.grid(row=0, column=0, padx=5, pady=2)

        sudo_frame = tk.Frame(self)
        sudo_frame.pack(fill="x", padx=10, pady=5)
        self.sudo_var = tk.BooleanVar()
        if sys.platform.startswith("win"):
            tk.Checkbutton(sudo_frame, text="Run with sudo (not available on Windows)", variable=self.sudo_var, state="disabled").pack(anchor="w")
        else:
            tk.Checkbutton(sudo_frame, text="Run with sudo", variable=self.sudo_var).pack(anchor="w")

        control_frame = tk.Frame(self)
        control_frame.pack(pady=10)

        run_button = tk.Button(control_frame, text="Run Nmap Scan", command=self.run_scan,
                             bg="#28A745", fg="white", font=("Arial", 10, "bold"))
        run_button.pack(side="left", padx=5)

        save_button = tk.Button(control_frame, text="Save Output", command=self.save_output,
                              bg="#007BFF", fg="white", font=("Arial", 10))
        save_button.pack(side="left", padx=5)

        clear_button = tk.Button(control_frame, text="Clear Output", command=self.clear_output,
                               bg="#FFC107", fg="black", font=("Arial", 10))
        clear_button.pack(side="left", padx=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=[("All Files", "*.*"),
                       ("Text Files", "*.txt"),
                       ("PDF Files", "*.pdf"),
                       ("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if file_path:
            self.input_file_entry.delete(0, tk.END)
            self.input_file_entry.insert(0, file_path)

    def create_status_bar(self):
        self.status_bar = tk.Label(self, text="Ready", relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

    def logout(self):
        result = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if result:
            self.withdraw()
            self.current_user = None
            self.show_login()

    def run_scan(self):
        if hasattr(self, 'output_window') and self.output_window.winfo_exists():
            self.output_window.destroy()

        # Create new popup output window
        self.output_window = tk.Toplevel(self)
        self.output_window.title("Output")
        self.output_window.geometry("650x400")

        self.output_text = scrolledtext.ScrolledText(self.output_window, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill="both", expand=True, padx=10, pady=10)

        target = self.target_entry.get().strip()
        input_file = self.input_file_entry.get().strip()
        cmd = ["nmap"]
        scan_target = ""

        if input_file:
            cmd += ["-iL", input_file]
            scan_target = f"InputFile_{os.path.basename(input_file)}"
        elif target:
            cmd.append(target)
            scan_target = target
        else:
            messagebox.showerror("Error", "Please specify a target or an input file!")
            return

        if self.sn_var.get():
            cmd.append("-sn")
        if self.sL_var.get():
            cmd.append("-sL")
        if self.Pn_var.get():
            cmd.append("-Pn")

        scan_choice = self.scan_combo.get()
        if scan_choice.startswith("-sS"):
            cmd.append("-sS")
        elif scan_choice.startswith("-sT"):
            cmd.append("-sT")
        elif scan_choice.startswith("-sU"):
            cmd.append("-sU")
        elif scan_choice.startswith("-sA"):
            cmd.append("-sA")

        ports = self.port_entry.get().strip()
        if ports:
            cmd += ["-p", ports]

        if self.sV_var.get():
            cmd.append("-sV")
        if self.O_var.get():
            cmd.append("-O")

        script_opts = self.script_entry.get().strip()
        if script_opts:
            cmd += ["--script", script_opts]

        timing = self.timing_entry.get().strip()
        if timing:
            cmd.append("-T" + timing)

        if self.ipv6_var.get():
            cmd.append("-6")

        custom_opts = self.custom_entry.get().strip()
        if custom_opts:
            cmd += custom_opts.split()

        use_sudo = False
        if self.sudo_var.get() and not sys.platform.startswith("win") and os.getpid() != 0:
            sudo_password = simpledialog.askstring("Sudo Password", "Enter sudo password:", show="*")
            if sudo_password is None:
                messagebox.showerror("Error", "Sudo password is required!")
                return
            cmd = ["sudo", "-S"] + cmd
            use_sudo = True

        self.status_bar.config(text="Running scan...")
        self.update_idletasks()

        log_header = f"""
=== Nmap Scan Log ===
User: {self.current_user}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target: {scan_target}
Command: {' '.join(cmd)}
{'='*50}
"""
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, log_header)
        self.output_text.insert(tk.END, "Executing scan...\n\n")
        self.update_idletasks()

        try:
            if not self.is_nmap_available():
                raise FileNotFoundError("Nmap is not installed or not in PATH.")

            if use_sudo:
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = process.communicate(sudo_password + "\n")
            else:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = process.communicate()

            full_log_content = log_header + out
            if err:
                full_log_content += "\nErrors/Warnings:\n" + err

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, full_log_content)

            log_filename = f"nmap_scan_{scan_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            log_path = os.path.join(self.logs_directory, log_filename)
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(full_log_content)

            self.status_bar.config(text=f"Scan completed. Log saved: {log_filename}")
            self.output_text.insert(tk.END, f"\n\nLog saved to {log_path}\n")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while running Nmap: {str(e)}")
            self.status_bar.config(text="Error during scan")

    def clear_output(self):
        if hasattr(self, 'output_text'):
            self.output_text.delete("1.0", tk.END)
            self.status_bar.config(text="Output cleared")

    def save_output(self):
        if hasattr(self, 'output_text'):
            content = self.output_text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showwarning("Warning", "No output to save!")
                return
            file_path = filedialog.asksaveasfilename(
                title="Save Output",
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Output saved to {file_path}")


    def is_nmap_available(self):
        try:
            subprocess.run(["nmap", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except Exception:
            return False


if __name__ == "__main__":
    app = NmapGUI()
    app.mainloop()
