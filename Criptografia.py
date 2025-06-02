import tkinter as tk
from tkinter import messagebox, filedialog
import json
import os
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

# ======== ENCRYPTOR CLASS ========

class Encryptor:
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Chave deve ter 16, 24 ou 32 bytes")
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        try:
            with open(file_name, 'rb') as fo:
                plaintext = fo.read()
            enc = self.encrypt(plaintext)
            with open(file_name + ".enc", 'wb') as fo:
                fo.write(enc)
            os.remove(file_name)
            return True
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao criptografar: {e}")
            return False

    def decrypt(self, ciphertext):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        try:
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()
            dec = self.decrypt(ciphertext)
            output_name = file_name[:-4] if file_name.endswith('.enc') else file_name + '.dec'
            with open(output_name, 'wb') as fo:
                fo.write(dec)
            os.remove(file_name)
            return True
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao descriptografar: {e}")
            return False

# ======== USUÁRIOS ========

def carregar_usuarios():
    if os.path.exists("usuarios.json"):
        with open("usuarios.json", "r") as f:
            return json.load(f)
    return {}

def salvar_usuarios(usuarios):
    with open("usuarios.json", "w") as f:
        json.dump(usuarios, f)

# ======== TELA DE CRIPTOGRAFIA ========

def tela_criptografia():
    login_frame.pack_forget()
    cadastro_frame.pack_forget()

    crypto_frame = tk.Frame(root)
    crypto_frame.pack(pady=20)

    tk.Label(crypto_frame, text="Senha para criptografia:").pack()
    entrada_senha = tk.Entry(crypto_frame, show="*")
    entrada_senha.pack()

    def selecionar_arquivo():
        return filedialog.askopenfilename()

    def criptografar():
        arquivo = selecionar_arquivo()
        if not arquivo:
            return
        senha = entrada_senha.get().encode()
        key = hashlib.sha256(senha).digest()
        enc = Encryptor(key)
        if enc.encrypt_file(arquivo):
            messagebox.showinfo("Sucesso", f"{arquivo} criptografado com sucesso!")

    def descriptografar():
        arquivo = selecionar_arquivo()
        if not arquivo:
            return
        senha = entrada_senha.get().encode()
        key = hashlib.sha256(senha).digest()
        enc = Encryptor(key)
        if enc.decrypt_file(arquivo):
            messagebox.showinfo("Sucesso", f"{arquivo} descriptografado com sucesso!")

    tk.Button(crypto_frame, text="Criptografar Arquivo", command=criptografar).pack(pady=5)
    tk.Button(crypto_frame, text="Descriptografar Arquivo", command=descriptografar).pack(pady=5)

# ======== TELA DE LOGIN ========

def login():
    usuario = entrada_usuario.get()
    senha = entrada_senha.get()
    usuarios = carregar_usuarios()

    if usuario in usuarios:
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        if usuarios[usuario] == senha_hash:
            messagebox.showinfo("Sucesso", "Login realizado com sucesso!")
            tela_criptografia()
        else:
            messagebox.showerror("Erro", "Senha incorreta!")
    else:
        messagebox.showerror("Erro", "Usuário não encontrado!")

# ======== TELA DE CADASTRO ========

def cadastrar():
    usuario = entrada_novo_usuario.get()
    senha = entrada_nova_senha.get()

    if not usuario or not senha:
        messagebox.showerror("Erro", "Preencha todos os campos!")
        return

    usuarios = carregar_usuarios()
    if usuario in usuarios:
        messagebox.showerror("Erro", "Usuário já existe!")
        return

    senha_hash = hashlib.sha256(senha.encode()).hexdigest()
    usuarios[usuario] = senha_hash
    salvar_usuarios(usuarios)
    messagebox.showinfo("Sucesso", "Usuário cadastrado com sucesso!")
    cadastro_frame.pack_forget()
    login_frame.pack()

# ======== TROCA DE TELAS ========

def abrir_cadastro():
    login_frame.pack_forget()
    cadastro_frame.pack()

def voltar_login():
    cadastro_frame.pack_forget()
    login_frame.pack()

# ======== INTERFACE ========

root = tk.Tk()
root.title("Sistema de Criptografia com Login")

# Login
login_frame = tk.Frame(root)
login_frame.pack(pady=20)

tk.Label(login_frame, text="Usuário:").pack()
entrada_usuario = tk.Entry(login_frame)
entrada_usuario.pack()

tk.Label(login_frame, text="Senha:").pack()
entrada_senha = tk.Entry(login_frame, show="*")
entrada_senha.pack()

tk.Button(login_frame, text="Login", command=login).pack(pady=5)
tk.Button(login_frame, text="Cadastrar", command=abrir_cadastro).pack(pady=5)

# Cadastro
cadastro_frame = tk.Frame(root)

tk.Label(cadastro_frame, text="Novo Usuário:").pack()
entrada_novo_usuario = tk.Entry(cadastro_frame)
entrada_novo_usuario.pack()

tk.Label(cadastro_frame, text="Nova Senha:").pack()
entrada_nova_senha = tk.Entry(cadastro_frame, show="*")
entrada_nova_senha.pack()

tk.Button(cadastro_frame, text="Salvar", command=cadastrar).pack(pady=5)
tk.Button(cadastro_frame, text="Voltar", command=voltar_login).pack(pady=5)

root.mainloop()
