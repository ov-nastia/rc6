import os

class RC6:
    def __init__(self, key, block_size=128, rounds=20):
        self.block_size = block_size
        self.rounds = rounds
        self.key = key
        self.expanded_key = self.key_expansion()

    def key_expansion(self):
        P = 0xB7E15163
        Q = 0x9E3779B9
        t = 2 * (self.rounds + 1)
        c = (self.block_size + 7) // 8
        S = [P + i * Q for i in range(t)]
        L = [0] * c
        for i in range(c):
            L[i] = int.from_bytes(self.key[i * 4:i * 4 + 4], byteorder='big')
        A = B = i = j = 0
        for k in range(3 * max(t, c)):
            A = S[i] = self.rotate_left(S[i] + A + B, 3)
            B = L[j] = self.rotate_left(L[j] + A + B, (A + B) % 32)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    def rotate_left(self, value, shift):
        return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

    def encrypt(self, plaintext):
        A = int.from_bytes(plaintext[:len(plaintext) // 2], byteorder='big')
        B = int.from_bytes(plaintext[len(plaintext) // 2:], byteorder='big')

        A = (A + self.expanded_key[0]) & 0xFFFFFFFF
        B = (B + self.expanded_key[1]) & 0xFFFFFFFF
        for i in range(1, self.rounds + 1):
            A = (A ^ B)
            A = self.rotate_left(A, B & 0x1F) + self.expanded_key[2 * i] & 0xFFFFFFFF
            B = (B ^ A)
            B = self.rotate_left(B, A & 0x1F) + self.expanded_key[2 * i + 1] & 0xFFFFFFFF

        ciphertext = A.to_bytes(4, byteorder='big') + B.to_bytes(4, byteorder='big')
        return ciphertext

    def decrypt(self, ciphertext):
        A = int.from_bytes(ciphertext[:len(ciphertext) // 2], byteorder='big')
        B = int.from_bytes(ciphertext[len(ciphertext) // 2:], byteorder='big')

        for i in range(self.rounds, 0, -1):
            B = (B - self.expanded_key[2 * i + 1]) & 0xFFFFFFFF
            B = self.rotate_right(B, A & 0x1F) ^ A
            A = (A - self.expanded_key[2 * i]) & 0xFFFFFFFF
            A = self.rotate_right(A, B & 0x1F) ^ B

        B = (B - self.expanded_key[1]) & 0xFFFFFFFF
        A = (A - self.expanded_key[0]) & 0xFFFFFFFF

        plaintext = A.to_bytes(4, byteorder='big') + B.to_bytes(4, byteorder='big')
        return plaintext

    def rotate_right(self, value, shift):
        return (value >> shift) | ((value << (32 - shift)) & 0xFFFFFFFF)

def bytes_to_text(byte_data, encoding='utf-16'):
    return byte_data.decode(encoding)
def text_to_bytes(text_data, encoding='utf-8'):
    return text_data.encode(encoding)

def generate_key():
    return os.urandom(8)

def encrypt_file(rc6, input_file, output_file):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    if len(plaintext) % 8 != 0:
        padding = 8 - (len(plaintext) % 8)
        plaintext += bytes([padding] * padding)

    ciphertext = b''
    for i in range(0, len(plaintext), 8):
        ciphertext += rc6.encrypt(plaintext[i:i+8])

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(rc6, input_file, output_file):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        plaintext += rc6.decrypt(ciphertext[i:i+8])
    print(plaintext)
    with open(output_file, 'wb') as f:
        f.write(plaintext)





'''if __name__ == "__main__":
    key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    print(bytes_to_text(key))
    rc6 = RC6(key)
    plaintext = b'Hellowor'
    ciphertext = rc6.encrypt(plaintext)
    #print(bytes_to_text(plaintext))
    print("Зашифроване повідомлення:", ciphertext)
    #print(bytes_to_text(ciphertext))
    decrypted_text = rc6.decrypt(ciphertext)
    print("Розшифроване повідомлення:", decrypted_text)
    #print(bytes_to_text(decrypted_text))'''


'''def main():
    print("RC6 Шифрування/Дешифрування")
    print("-----------------------------")

    key = generate_key()
    key=b'key'
    print("Згенерований ключ:", key)

    action = input("Введіть 'e' для шифрування файлу або 'd' для дешифрування файлу: ")
    input_file = input("Введіть шлях до вхідного файлу: ")
    output_file = input("Введіть шлях до вихідного файлу: ")

    rc6 = RC6(key)

    if action == 'e':
        encrypt_file(rc6, input_file, output_file)
        print("Файл зашифровано!")
    elif action == 'd':
        decrypt_file(rc6, input_file, output_file)
        print("Файл розшифровано!")
    else:
        print("Неправильне дію. Виберіть 'e' або 'd'.")'''

import tkinter as tk
from tkinter import filedialog, messagebox


class RC6App:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("RC6 Шифрування/Дешифрування")
        self.create_widgets()
        self.window.mainloop()

    def create_widgets(self):
        self.key_label = tk.Label(text="Ключ:")
        self.key_label.grid(row=0, column=0, padx=(20, 10), pady=(20, 10), sticky="W")

        self.key_entry = tk.Entry(width=40)
        self.key_entry.grid(row=0, column=1, padx=(0, 20), pady=(20, 10))

        self.generate_key_button = tk.Button(text="Згенерувати ключ", command=self.generate_key)
        self.generate_key_button.grid(row=0, column=2, padx=(0, 20), pady=(20, 10))

        self.encrypt_button = tk.Button(text="Зашифрувати файл", command=self.encrypt_file)
        self.encrypt_button.grid(row=1, column=0, padx=(20, 10), pady=(0, 20), columnspan=2, sticky="W")

        self.decrypt_button = tk.Button(text="Розшифрувати файл", command=self.decrypt_file)
        self.decrypt_button.grid(row=1, column=1, padx=(0, 20), pady=(0, 20), columnspan=2, sticky="E")
        self.input_label = tk.Label(text="Вхідний текст:(блок-8)")
        self.input_label.grid(row=2, column=0, padx=(20, 10), pady=(20, 10), sticky="W")

        self.input_text = tk.Text(height=5, width=40)
        self.input_text.grid(row=2, column=1, padx=(0, 20), pady=(20, 10))

        self.encrypt_button = tk.Button(text="Зашифрувати текст", command=self.encrypt_text)
        self.encrypt_button.grid(row=2, column=2, padx=(0, 20), pady=(20, 10))

        self.output_label = tk.Label(text="Результат:")
        self.output_label.grid(row=3, column=0, padx=(20, 10), pady=(20, 10), sticky="W")

        self.output_text = tk.Text(height=5, width=40)
        self.output_text.grid(row=3, column=1, padx=(0, 20), pady=(20, 10))

        self.decrypt_button = tk.Button(text="Розшифрувати текст", command=self.decrypt_text)
        self.decrypt_button.grid(row=3, column=2, padx=(0, 20), pady=(20, 10))

    def generate_key(self):
        key = os.urandom(8)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())
    def get_key(self):
        key_hex = self.key_entry.get()
        print(key_hex.encode(encoding = 'UTF-8'))
        return key_hex.encode(encoding = 'UTF-8')

    def encrypt_file(self):
        key = self.get_key()
        rc6 = RC6(key)
        input_file = filedialog.askopenfilename(title="Відкрити файл для шифрування")
        output_file = filedialog.asksaveasfilename(title="Зберегти зашифрований файл")
        if input_file and output_file:
            encrypt_file(rc6, input_file, output_file)
            messagebox.showinfo("RC6", "Файл зашифровано!")

    def decrypt_file(self):
        key = self.get_key()
        rc6 = RC6(key)
        input_file = filedialog.askopenfilename(title="Відкрити файл для дешифрування")
        output_file = filedialog.asksaveasfilename(title="Зберегти розшифрований файл")
        if input_file and output_file:
            decrypt_file(rc6, input_file, output_file)
            messagebox.showinfo("RC6", "Файл розшифровано!")

    def encrypt_text(self):
        key = self.get_key()
        rc6 = RC6(key)
        plaintext = self.input_text.get("1.0", tk.END).encode(encoding = 'UTF-8').split()[0]
        ciphertext = rc6.encrypt(plaintext)
        print(ciphertext)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", ciphertext.decode('latin1'))
        print(rc6.decrypt(ciphertext))

    def decrypt_text(self):
        key = self.get_key()
        rc6 = RC6(key)
        ciphertext = self.output_text.get("1.0", tk.END).encode('latin1').split()[0]
        print(ciphertext)
        decrypted_text = rc6.decrypt(ciphertext)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", decrypted_text)
if __name__ == "__main__":
    app = RC6App()