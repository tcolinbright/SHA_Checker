import hashlib
import tkinter as tk
from tkinter import filedialog

class App:
    def __init__(self, master):
        self.master = master
        master.title("Hash Checker")

        self.file_path = tk.StringVar()
        self.hash_algorithm = tk.StringVar(value="sha256")
        self.hash_value = tk.StringVar()

        file_frame = tk.Frame(master)
        file_frame.pack(padx=10, pady=10)
        file_label = tk.Label(file_frame, text="File:")
        file_label.pack(side=tk.LEFT)
        file_entry = tk.Entry(file_frame, textvariable=self.file_path, width=40)
        file_entry.pack(side=tk.LEFT, padx=10)
        file_button = tk.Button(file_frame, text="Browse", command=self.browse_file)
        file_button.pack(side=tk.LEFT)

        algorithm_frame = tk.Frame(master)
        algorithm_frame.pack(padx=10, pady=10)
        algorithm_label = tk.Label(algorithm_frame, text="Algorithm:")
        algorithm_label.pack(side=tk.LEFT)
        algorithm_menu = tk.OptionMenu(algorithm_frame, self.hash_algorithm, "sha256", "sha1", "md5")
        algorithm_menu.pack(side=tk.LEFT, padx=10)

        hash_frame = tk.Frame(master)
        hash_frame.pack(padx=10, pady=10)
        hash_label = tk.Label(hash_frame, text="Hash Value:")
        hash_label.pack(side=tk.LEFT)
        hash_entry = tk.Entry(hash_frame, textvariable=self.hash_value, width=40, state="readonly")
        hash_entry.pack(side=tk.LEFT, padx=10)

        check_button = tk.Button(master, text="Check Hash", command=self.check_hash)
        check_button.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def check_hash(self):
        file_path = self.file_path.get()
        hash_algorithm = self.hash_algorithm.get()
        hash_function = getattr(hashlib, hash_algorithm)

        try:
            with open(file_path, 'rb') as f:
                hash_value = hash_function(f.read()).hexdigest()
                self.hash_value.set(hash_value)
        except FileNotFoundError:
            self.hash_value.set("File not found")

root = tk.Tk()
app = App(root)
root.mainloop()
