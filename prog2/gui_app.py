import tkinter as tk
from tkinter import ttk, messagebox
import itertools
import string
import time
import re
import threading

CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"

class PasswordAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Security Analyzer")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        self.attack_running = False
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = tk.Label(main_frame, text="🔐 Password Security Analyzer", 
                              font=("Arial", 20, "bold"), bg='#f0f0f0', fg='#2c3e50')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password input
        tk.Label(main_frame, text="Enter Password:", font=("Arial", 12), 
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(main_frame, textvariable=self.password_var, 
                                      font=("Arial", 12), width=30, show="*")
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.password_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Show/Hide password
        self.show_password = tk.BooleanVar()
        show_check = tk.Checkbutton(main_frame, text="Show Password", 
                                   variable=self.show_password, 
                                   command=self.toggle_password_visibility,
                                   bg='#f0f0f0', fg='black')
        show_check.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Analysis frame
        analysis_frame = ttk.LabelFrame(main_frame, text="Password Analysis", padding="10")
        analysis_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=20)
        
        # Strength indicator
        tk.Label(analysis_frame, text="Strength:", font=("Arial", 12, "bold"), bg='white', fg='black').grid(row=0, column=0, sticky=tk.W)
        self.strength_label = tk.Label(analysis_frame, text="Enter password", 
                                      font=("Arial", 12, "bold"), fg='#7f8c8d', bg='white')
        self.strength_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # Details
        details = ["Length", "Lowercase", "Uppercase", "Digits", "Special Chars"]
        self.detail_labels = {}
        
        for i, detail in enumerate(details):
            tk.Label(analysis_frame, text=f"{detail}:", font=("Arial", 10), bg='white', fg='black').grid(row=i+1, column=0, sticky=tk.W)
            self.detail_labels[detail] = tk.Label(analysis_frame, text="-", font=("Arial", 10), bg='white', fg='black')
            self.detail_labels[detail].grid(row=i+1, column=1, sticky=tk.W, padx=(10, 0))
        
        # Brute force frame
        attack_frame = ttk.LabelFrame(main_frame, text="Brute Force Attack", padding="10")
        attack_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=20)
        
        # Attack controls
        control_frame = tk.Frame(attack_frame, bg='#f0f0f0')
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        tk.Label(control_frame, text="Max Attempts:", bg='#f0f0f0', fg='black').grid(row=0, column=0, sticky=tk.W)
        self.max_attempts_var = tk.StringVar(value="10000")
        attempts_entry = tk.Entry(control_frame, textvariable=self.max_attempts_var, width=10)
        attempts_entry.grid(row=0, column=1, padx=(10, 20))
        
        self.attack_button = tk.Button(control_frame, text="Start Attack", 
                                      command=self.start_attack, bg='#3498db', 
                                      fg='white', font=("Arial", 10, "bold"))
        self.attack_button.grid(row=0, column=2, padx=10)
        
        self.stop_button = tk.Button(control_frame, text="Stop", 
                                    command=self.stop_attack, bg='#e74c3c', 
                                    fg='white', font=("Arial", 10, "bold"), state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)
        
        # Progress
        tk.Label(attack_frame, text="Progress:", font=("Arial", 10, "bold"), bg='white', fg='black').grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        self.progress = ttk.Progressbar(attack_frame, mode='determinate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status
        self.status_text = tk.Text(attack_frame, height=8, width=70, font=("Courier", 9), bg='white', fg='black')
        self.status_text.grid(row=3, column=0, columnspan=2, pady=10)
        
        scrollbar = ttk.Scrollbar(attack_frame, orient="vertical", command=self.status_text.yview)
        scrollbar.grid(row=3, column=2, sticky=(tk.N, tk.S))
        self.status_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        analysis_frame.columnconfigure(1, weight=1)
        attack_frame.columnconfigure(0, weight=1)
        control_frame.columnconfigure(2, weight=1)
    
    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def on_password_change(self, event=None):
        password = self.password_var.get()
        if password:
            self.analyze_password(password)
        else:
            self.clear_analysis()
    
    def analyze_password(self, password):
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        score = sum([has_lower, has_upper, has_digit, has_special])
        
        if length < 6 or score < 2:
            strength = "Weak"
            color = '#e74c3c'
        elif length >= 6 and score == 3:
            strength = "Moderate"
            color = '#f39c12'
        elif length >= 8 and score == 4:
            strength = "Strong"
            color = '#27ae60'
        else:
            strength = "Moderate"
            color = '#f39c12'
        
        self.strength_label.config(text=strength, fg=color)
        self.detail_labels["Length"].config(text=str(length))
        self.detail_labels["Lowercase"].config(text="✓" if has_lower else "✗", 
                                              fg='#27ae60' if has_lower else '#e74c3c')
        self.detail_labels["Uppercase"].config(text="✓" if has_upper else "✗",
                                              fg='#27ae60' if has_upper else '#e74c3c')
        self.detail_labels["Digits"].config(text="✓" if has_digit else "✗",
                                           fg='#27ae60' if has_digit else '#e74c3c')
        self.detail_labels["Special Chars"].config(text="✓" if has_special else "✗",
                                                  fg='#27ae60' if has_special else '#e74c3c')
    
    def clear_analysis(self):
        self.strength_label.config(text="Enter password", fg='#7f8c8d', bg='white')
        for label in self.detail_labels.values():
            label.config(text="-", fg='black', bg='white')
    
    def start_attack(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password first!")
            return
        
        try:
            max_attempts = int(self.max_attempts_var.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for max attempts!")
            return
        
        self.attack_running = True
        self.attack_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.progress['value'] = 0
        
        # Start attack in separate thread
        thread = threading.Thread(target=self.brute_force_attack, args=(password, max_attempts))
        thread.daemon = True
        thread.start()
    
    def stop_attack(self):
        self.attack_running = False
        self.attack_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_status("Attack stopped by user.\n")
    
    def brute_force_attack(self, password, max_attempts):
        attempts = 0
        start_time = time.time()
        
        self.log_status(f"Starting brute-force attack (max attempts: {max_attempts})...\n")
        
        for length in range(1, len(password) + 1):
            if not self.attack_running:
                break
                
            for guess_tuple in itertools.product(CHARSET, repeat=length):
                if not self.attack_running or attempts >= max_attempts:
                    break
                
                guess = ''.join(guess_tuple)
                attempts += 1
                
                # Update progress every 100 attempts
                if attempts % 100 == 0:
                    progress = min((attempts / max_attempts) * 100, 100)
                    self.root.after(0, lambda p=progress: self.progress.config(value=p))
                    self.root.after(0, lambda g=guess, a=attempts: 
                                   self.log_status(f"Trying: {g} (Attempt: {a})\n"))
                
                if guess == password:
                    elapsed = time.time() - start_time
                    self.root.after(0, lambda: self.attack_complete(True, guess, attempts, elapsed))
                    return
        
        elapsed = time.time() - start_time
        self.root.after(0, lambda: self.attack_complete(False, None, attempts, elapsed))
    
    def attack_complete(self, found, password, attempts, elapsed):
        self.attack_running = False
        self.attack_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress['value'] = 100
        
        if found:
            self.log_status(f"\n🎯 PASSWORD FOUND: '{password}'\n")
            self.log_status(f"Attempts: {attempts:,}\n")
            self.log_status(f"Time: {elapsed:.2f} seconds\n")
            messagebox.showinfo("Success!", f"Password cracked: '{password}'")
        else:
            self.log_status(f"\n❌ Password not found within {attempts:,} attempts\n")
            self.log_status(f"Time: {elapsed:.2f} seconds\n")
    
    def log_status(self, message):
        self.status_text.insert(tk.END, message)
        self.status_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerGUI(root)
    root.mainloop()