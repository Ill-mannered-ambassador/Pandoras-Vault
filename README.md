Pandora's Vault (WOC 2025)
End-to-End Encrypted, Blind-Server File Storage System.

Follow the given instructions to setup and check the fucntioning.

Installation & Setup
# 1. Clone
    git clone [https://github.com/YOUR_USERNAME/Pandoras-Vault.git](https://github.com/YOUR_USERNAME/Pandoras-Vault.git)
    cd Pandoras-Vault

# 2. COMPILE AUTH LIBRARY
    gcc -shared -o libtotp.so -fPIC sha_1.c

# 3. Install Dependencies
    pip install flask

# 4. Run Server
    python3 app.py

Access at: http://localhost:5000

Note: 
1) Try logging in after entering wrong OTP :). (Yes you will still get in)
2) Linux recommended (please).
