🔐 AES-256 FILE ENCRYPTION TOOL (CODTECH INTERNSHIP – TASK 4)

### 🧾 INTERN DETAILS

Company       : CodTech IT Solutions

Intern Name   : SACHINDORE P

Intern ID     : CT06DG1111

Domain        : Cyber Security & Ethical Hacking

Duration      : 6 Weeks

Mentor        : Neela Santhosh

--------------------------------------------------------------------

### 📌 OBJECTIVE
Develop a secure file encryption tool using AES-256 (CBC mode), allowing:
- Password-based encryption of any file
- Secure decryption with automatic extension recovery
- User-friendly interface for interaction

--------------------------------------------------------------------

### ⚙️ FEATURES
✔ AES-256 encryption with CBC mode  
✔ Password-based key derivation (PBKDF2 with SHA-256)  
✔ Random salt + IV for every encryption  
✔ PKCS7 padding with padding error detection  
✔ Original file extension embedded and recovered  
✔ Error shown on incorrect password  
✔ Cross-format file support (images, PDFs, videos, docs, etc.)  
✔ Simple GUI built using Tkinter  

--------------------------------------------------------------------

### 📁 PROJECT STRUCTURE

aes_encryption_tool/
├── aes_tool.py       -> AES encryption/decryption logic
├── gui.py            -> Tkinter interface for user actions
└── README.txt        -> Internship documentation (this file)

--------------------------------------------------------------------

### 🔐 HOW IT WORKS

[ENCRYPTION PROCESS]
1. User selects a file and enters password.
2. A 256-bit key is derived using PBKDF2 from password + random salt.
3. The file is padded and encrypted using AES-256 in CBC mode.
4. Format saved as: [salt][IV][ext(10 bytes)][encrypted_data]
5. Output saved as: encrypted_file.bin

[DECRYPTION PROCESS]
1. User selects `.bin` file and provides password.
2. Salt, IV, and extension are extracted.
3. AES decrypts and removes padding.
4. Original file is saved with correct extension (e.g., `.jpg`, `.pdf`).

--------------------------------------------------------------------

### 🚀 HOW TO RUN THE TOOL

STEP 1: CLONE THE REPOSITORY
    git clone https://github.com/Sachindore1/ADVANCED-ENCRYPTION-TOOL.git

STEP 2: INSTALL REQUIRED LIBRARIES
    pip install cryptography tkinterdnd2

STEP 3: LAUNCH THE TOOL
    python gui.py

--------------------------------------------------------------------

### 📂 EXAMPLE USAGE

🔒 ENCRYPTION
    Input File   : image.jpg
    Password     : secret@123
    Output File  : encrypted_file.bin

🔓 DECRYPTION
    Input File   : encrypted_file.bin
    Password     : secret@123
    Output File  : decrypted_file.jpg

❌ WRONG PASSWORD OUTPUT
    "Decryption failed. Wrong password or corrupted file."

--------------------------------------------------------------------

### 🖼️ UI OUTPUT SECTION

<img width="742" height="493" alt="Image" src="https://github.com/user-attachments/assets/13d14070-0a39-473c-9ab7-4339ad2e2e18" />

--------------------------------------------------------------------

### 🛡️ SECURITY NOTES

- AES-256 provides strong, industry-grade encryption
- Passwords are never stored or logged
- Every encryption has unique salt and IV — output is always different
- Decryption is impossible without the correct password

--------------------------------------------------------------------

### ✅ INTERNSHIP SUMMARY

Internship Provider : CodTech IT Solutions
Task Name           : AES-256 File Encryption Tool
Tools Used          : Python, Cryptography, Tkinter
Status              : ✅ Completed Successfully

--------------------------------------------------------------------

### ✍️ AUTHOR

Name     : Sachindore P  
Course   : MCA (ISMS), Jain University  
GitHub   : https://github.com/Sachindore1  
LinkedIn : https://linkedin.com/in/sachindore

====================================================================
