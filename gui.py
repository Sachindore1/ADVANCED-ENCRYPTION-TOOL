# 🔐 AES-256 GUI TOOL

# --- Import libraries ---
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD  # For drag and drop support
from aes_tool import encrypt_file, decrypt_file  # Custom encryption logic
import os
import threading  # To run encryption/decryption in a separate thread

# --- Select file using file dialog ---
def select_file():
    filepath.set(filedialog.askopenfilename())

# --- Save encrypted/decrypted data with correct extension ---
def save_data(data, default_name, correct_ext=".bin", open_after=False):
    path = filedialog.asksaveasfilename(initialfile=default_name)
    if path:
        # Ensure the file has correct extension
        if not path.lower().endswith(correct_ext):
            path += correct_ext
        with open(path, 'wb') as f:
            f.write(data)
        messagebox.showinfo("✅ Success", f"File saved as:\n{path}")
        # Optionally open the file after saving
        if open_after:
            try:
                os.startfile(path)
            except Exception as e:
                messagebox.showwarning("⚠️ Could not open file", str(e))

# --- Show progress animation ---
def show_loading():
    progress.pack(pady=10)
    progress.start(10)
    root.update()

# --- Hide progress animation ---
def hide_loading():
    progress.stop()
    progress.pack_forget()

# --- Encrypt button logic with threading and loading animation ---
def encrypt_action():
    def run_encrypt():
        try:
            show_loading()
            data = encrypt_file(filepath.get(), password.get())
            save_data(data, "encrypted_file.bin", correct_ext=".bin")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
        finally:
            hide_loading()
    threading.Thread(target=run_encrypt).start()

# --- Decrypt button logic with extension recovery and animation ---
def decrypt_action():
    def run_decrypt():
        try:
            show_loading()
            data, ext = decrypt_file(filepath.get(), password.get())
            default_name = f"decrypted_file{ext}"
            save_data(data, default_name, correct_ext=ext, open_after=True)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
        finally:
            hide_loading()
    threading.Thread(target=run_decrypt).start()

# --- Handle drag-and-drop file input ---
def on_drop(event):
    path = event.data.strip('{}')  # Clean file path from brackets
    filepath.set(path)

# ====================
# GUI WINDOW SETUP
# ====================

root = TkinterDnD.Tk()
root.title("🔐 AES-256 File Encryption Tool")
root.geometry("600x370")
root.resizable(False, False)
root.configure(bg="#1e1e2f")  # Dark theme background

# --- UI Fonts and Colors ---
label_font = ("Segoe UI", 11)
entry_font = ("Segoe UI", 10)
button_font = ("Segoe UI", 10, "bold")
button_bg = "#3a7ff6"
button_fg = "white"

# --- Variables for file path and password ---
filepath = tk.StringVar()
password = tk.StringVar()

# --- Title Label ---
tk.Label(root, text="AES-256 File Encryption Tool", bg="#1e1e2f", fg="white",
         font=("Segoe UI", 16, "bold")).pack(pady=10)

# ============================
# FILE INPUT FIELD + BUTTON
# ============================
frame_file = tk.Frame(root, bg="#1e1e2f")
frame_file.pack(pady=5, padx=30, anchor="w")

tk.Label(frame_file, text="📁 File:", bg="#1e1e2f", fg="white", font=label_font,
         width=12, anchor="w").grid(row=0, column=0, sticky="w")

# Entry for file path (supports drag-and-drop)
entry_file = tk.Entry(frame_file, textvariable=filepath, font=entry_font,
                      width=35, bd=2, relief="groove")
entry_file.grid(row=0, column=1, padx=10)
entry_file.drop_target_register(DND_FILES)
entry_file.dnd_bind("<<Drop>>", on_drop)

# Browse button
tk.Button(frame_file, text="Browse", font=button_font, bg=button_bg,
          fg=button_fg, relief="flat", command=select_file).grid(row=0, column=2)

# ============================
# PASSWORD INPUT FIELD
# ============================
frame_pass = tk.Frame(root, bg="#1e1e2f")
frame_pass.pack(pady=15, padx=30, anchor="w")

tk.Label(frame_pass, text="🔑 Password:", bg="#1e1e2f", fg="white", font=label_font,
         width=12, anchor="w").grid(row=0, column=0, sticky="w")

# Entry for password (masked with '*')
tk.Entry(frame_pass, textvariable=password, show="*", font=entry_font,
         width=35, bd=2, relief="groove").grid(row=0, column=1, padx=10)

# ============================
# ENCRYPT / DECRYPT BUTTONS
# ============================
frame_buttons = tk.Frame(root, bg="#1e1e2f")
frame_buttons.pack(pady=10)

# Encrypt button
tk.Button(frame_buttons, text="🔐 Encrypt", width=18, font=button_font,
          bg="#28a745", fg="white", relief="flat", command=encrypt_action).pack(side="left", padx=15)

# Decrypt button
tk.Button(frame_buttons, text="🔓 Decrypt", width=18, font=button_font,
          bg="#dc3545", fg="white", relief="flat", command=decrypt_action).pack(side="left", padx=15)

# ============================
# PROGRESS BAR
# ============================
progress = ttk.Progressbar(root, orient="horizontal", mode="indeterminate", length=450)
style = ttk.Style()
style.theme_use('clam')
style.configure("TProgressbar", troughcolor="#2c2c3c", background="#3a7ff6", bordercolor="#1e1e2f", thickness=6)
progress.pack(pady=10)
progress.pack_forget()  # Hide progress initially

# Start the GUI loop
root.mainloop()
