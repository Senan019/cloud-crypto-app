import os
import base64
from flask import Flask, render_template, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# Master Key (HSM daxilində saxlanılan ana açar)
MASTER_KEY = AESGCM.generate_key(bit_length=256)

def encrypt_data(plain_text: str):
    # Dinamik Data Key (DEK)
    data_key = AESGCM.generate_key(bit_length=256)
    
    # Məlumatın DEK ilə şifrələnməsi
    aesgcm_data = AESGCM(data_key)
    nonce = os.urandom(12)
    encrypted_text_bytes = aesgcm_data.encrypt(nonce, plain_text.encode('utf-8'), None)
    
    # Data Key-in Master Key ilə şifrələnməsi (Envelope Encryption)
    aesgcm_master = AESGCM(MASTER_KEY)
    master_nonce = os.urandom(12)
    encrypted_dek_bytes = aesgcm_master.encrypt(master_nonce, data_key, None)
    
    return {
        "encrypted_data": base64.b64encode(nonce + encrypted_text_bytes).decode('utf-8'),
        "encrypted_dek": base64.b64encode(master_nonce + encrypted_dek_bytes).decode('utf-8')
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        secret_text = request.form.get('secret_data')
        if secret_text:
            result = encrypt_data(secret_text)
            result['original'] = secret_text
            
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)