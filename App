import hashlib
import time
from datetime import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Encryption setup
def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Blockchain classes
class Block:
    def __init__(self, index, previous_hash, timestamp, message, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp  # Приводим timestamp к строке в фиксированном формате
        self.message = message
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.message}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")

class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return Block(0, "0"*64, timestamp, "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                print("Current block hash is invalid!")
                return False

            if current_block.previous_hash != previous_block.hash:
                print("Previous block hash is invalid!")
                return False

        return True

# Messenger class with improved UI
theme_bg = "#2c3e50"
theme_fg = "#ecf0f1"
button_bg = "#3498db"
button_fg = "#ffffff"

class MessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Messenger")
        self.root.geometry("700x500")
        self.root.configure(bg=theme_bg)

        # Encryption key
        self.key = generate_key()

        # Blockchain instance
        self.blockchain = Blockchain()

        # GUI Elements
        self.chat_history = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', bg=theme_bg, fg=theme_fg, font=("Arial", 12))
        self.chat_history.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.message_frame = tk.Frame(root, bg=theme_bg)
        self.message_frame.pack(fill=tk.X, padx=10, pady=5)

        self.message_entry = tk.Entry(self.message_frame, width=50, font=("Arial", 12))
        self.message_entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(self.message_frame, text="Send", command=self.send_message, bg=button_bg, fg=button_fg, font=("Arial", 12))
        self.send_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.check_chain_button = tk.Button(root, text="Check Chain", command=self.check_chain, bg=button_bg, fg=button_fg, font=("Arial", 12))
        self.check_chain_button.pack(side=tk.BOTTOM, pady=5)

    def send_message(self):
        message = self.message_entry.get()
        if len(message) >= 64:
            messagebox.showerror("Error", "Message must be exactly 64 characters long.")
            return

        # Encrypt the message
        encrypted_message = encrypt_message(message, self.key)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Add the message as a block to the blockchain
        new_block = Block(len(self.blockchain.chain), "", timestamp, encrypted_message.decode())
        self.blockchain.add_block(new_block)

        # Display the original message in the chat history
        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, f"You: {message}\n", ("message",))
        self.chat_history.tag_config("message", foreground=theme_fg)
        self.chat_history.config(state='disabled')

        # Clear the entry field
        self.message_entry.delete(0, tk.END)

    def check_chain(self):
        valid = self.blockchain.is_chain_valid()
        if valid:
            messagebox.showinfo("Chain Status", "The blockchain is valid.")
        else:
            messagebox.showerror("Chain Status", "The blockchain is invalid!")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = MessengerApp(root)
    root.mainloop()
