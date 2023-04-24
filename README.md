# Hash Checker

The Hash Checker application allows users to calculate the hash value of a file and compare it with a given hash value to verify the file's integrity. The user interface of the application is implemented using the ```tkinter``` library.

## Dependencies

The application requires the following dependencies:

- Python 3.x
- tkinter library
- hashlib library

Both ```tkinter``` and ```hashlib``` libraries are included in Python 3.x, so no additional installation is required.

## Usage

To use the application, simply run the script using Python:

```bash
python3 hash_checker.py
```
The Hash Checker window will open, allowing the user to select a file, choose a hash algorithm, enter a hash value to compare, and check the hash value of the selected file.
Selecting a File

### Selecting a File

To select a file, click the Browse button and navigate to the file you want to check. Once you have selected a file, its path will be displayed in the File entry box.

### Choosing a Hash Algorithm

By default, the Hash Checker application uses the SHA-256 algorithm to calculate the hash value of the selected file. To choose a different algorithm, click the drop-down menu next to Algorithm and select the desired algorithm.

The available algorithms are:

- SHA-256
- SHA-1
- MD5


### Entering a Hash Value

If you already have a hash value for the file you want to check, you can enter it in the Hash Value entry box. This value will be used to compare against the calculated hash value.

Note: To clear the Hash Value entry box, simply click on it.


### Checking the Hash Value

Once you have selected a file, chosen a hash algorithm, and optionally entered a hash value, click the Check Hash button to calculate the hash value of the selected file and compare it with the entered hash value (if any).

If the calculated hash value matches the entered hash value (if any), the Result entry box will turn green. If the values do not match, the entry box will turn red. If there is an error while calculating the hash value (e.g., the selected file cannot be found), the Result entry box will display an error message.
Copying the Hash Value

To copy the calculated hash value to the clipboard, click the Copy button next to the Hash Value entry box.


## Code Documentation:

The code defines a graphical user interface (GUI) application called "Hash Checker" which allows the user to browse for a file, select a hashing algorithm (SHA-256, SHA-1, or MD5), calculate the hash value of the selected file using the selected algorithm, compare the calculated hash value with a user-provided check value, and display the result of the comparison.

The GUI is implemented using the tkinter module, which provides a set of Python bindings for the Tk GUI toolkit. The code defines a class called App, which encapsulates the application's logic and GUI elements.
### Class: App
Constructor

```python

def __init__(self, master):
```

The constructor of the App class initializes the GUI elements and sets their initial values. The master parameter is the root window of the application.

```python

self.master = master
master.title("Hash Checker")
```

The ```self.master``` attribute stores the root window of the application. The ```title()``` method sets the title of the window to "Hash Checker".

```python

self.file_path = tk.StringVar()
self.hash_algorithm = tk.StringVar(value="sha256")
self.hash_value = tk.StringVar()
self.check_value = tk.StringVar()
self.hash_matched = tk.BooleanVar(value=False)
```

These lines define five ```StringVar``` and ```BooleanVar``` objects, which are used to store and manipulate the values of various GUI elements.

- self.file_path: stores the path of the selected file.
- self.hash_algorithm: stores the selected hashing algorithm.
- self.hash_value: stores the calculated hash value of the selected file.
- self.check_value: stores the user-provided check value.
- self.hash_matched: stores a boolean value indicating whether the calculated hash value matches the check value.

File Selection

python

file_frame = tk.Frame(master)
file_frame.pack(padx=10, pady=10)
file_label = tk.Label(file_frame, text="File:")
file_label.pack(side=tk.LEFT)
file_entry = tk.Entry(file_frame, textvariable=self.file_path, width=60)
file_entry.pack(side=tk.LEFT, padx=10)
file_button = tk.Button(file_frame, text="Browse", command=self.browse_file)
file_button.pack(side=tk.LEFT)

These lines define a frame, label, entry, and button for selecting a file.

    file_frame: a Frame widget used to group the file-related GUI elements together.
    file_label: a Label widget displaying the text "File:".
    file_entry: an Entry widget used to display the path of the selected file.
    file_button: a Button widget used to browse for a file.

The command parameter of the Button widget is set to self.browse_file, which is a method that opens a file selection dialog when called.

python

def browse_file(self):
    file_path = filedialog.askopenfilename()
    if file_path:
        self.file_path.set(file_path)

The browse_file method opens a file selection dialog using the askopenfilename function of the filedialog module. If a file is selected, its path is set as the value of the self.file_path StringVar.

Algorithm Selection

The algorithm_frame widget group contains a label and an option menu for selecting the hashing algorithm to use. By default, sha256 is selected.

python

algorithm_frame = tk.Frame(master)
algorithm_frame.pack(padx=10, pady=10)
algorithm_label = tk.Label(algorithm_frame, text="Algorithm:")
algorithm_label.pack(side=tk.LEFT)
algorithm_menu = tk.OptionMenu(algorithm_frame, self.hash_algorithm, "sha256", "sha1", "md5")
algorithm_menu.pack(side=tk.LEFT, padx=10)

Hash Value

The hash_frame widget group contains a label, an entry field for displaying the computed hash value, and a button for copying the hash value to the system clipboard. The entry field is read-only and its value is set to the value of the self.hash_value variable. By default, the value of the self.hash_value variable is an empty string.

python

hash_frame = tk.Frame(master)
hash_frame.pack(padx=10, pady=10)
hash_label = tk.Label(hash_frame, text="Hash Value:")
hash_label.pack(side=tk.LEFT)
hash_entry = tk.Entry(hash_frame, textvariable=self.hash_value, width=70, state="readonly")
hash_entry.pack(side=tk.LEFT, padx=10)
hash_entry.bind('<Button-1>', lambda event: self.hash_value.set(''))

copy_button = tk.Button(hash_frame, text="Copy", command=self.copy_hash)
copy_button.pack(side=tk.LEFT)

The hash_entry field is also bound to the <Button-1> event, so that when the user clicks on it, the value of the self.hash_value variable is set to an empty string. This allows the user to easily clear the contents of the entry field.

The copy_button button is bound to the copy_hash method, which copies the value of the self.hash_value variable to the system clipboard when clicked.
Check Value

The check_frame widget group contains a label and an entry field for entering a hash value to compare against the computed hash value. The value of the entry field is stored in the self.check_value variable.

python

check_frame = tk.Frame(master)
check_frame.pack(padx=10, pady=10)
check_label = tk.Label(check_frame, text="Check Value:")
check_label.pack(side=tk.LEFT)
check_entry = tk.Entry(check_frame, textvariable=self.check_value, width=70)
check_entry.pack(side=tk.LEFT, padx=10)

Result Display

The result_frame widget group contains a label and an entry field for displaying the result of the hash check. The value of the entry field is set to the value of the self.hash_matched variable, which is a boolean variable that indicates whether the computed hash value matches the check value.

python

result_frame = tk.Frame(master)
result_frame.pack(padx=10, pady=10)
result_label = tk.Label(result_frame, text="Result:")
result_label.pack(side=tk.LEFT)
self.result_entry = tk.Entry(result_frame, textvariable=self.hash_matched, width=40, state="readonly")
self.result_entry.pack(side=tk.LEFT, padx=10)

Check Hash Button

The check_button widget is a simple button that, when clicked, calls the check_hash method to compute the hash value and compare it to the check value.

python

check_button = tk.Button(master, text="Check Hash", command=self.check_hash)
check_button.pack(pady=10)


File Browser and Open File

When the user clicks the "Browse" button, the browse_file method is called. This method opens a file dialog window using the filedialog.askopenfilename function from the tkinter module. This function returns the path to the selected file or an empty string if the user cancels the operation. If a file path is returned, it is set as the value of the self.file_path variable.

python

def browse_file(self):
    file_path = filedialog.askopenfilename()
    if file_path:
        self.file_path.set(file_path)

Copy Hash Value

The "Copy" button allows the user to copy the computed hash value to the clipboard. The copy_hash method is called when the button is clicked. This method clears the clipboard using self.master.clipboard_clear(), appends the current hash value to the clipboard using self.master.clipboard_append(self.hash_value.get()), and displays a message to the user indicating that the hash value has been copied.

python

def copy_hash(self):
    self.master.clipboard_clear()
    self.master.clipboard_append(self.hash_value.get())

Check Hash Value

The "Check Hash" button triggers the computation of the hash value of the selected file using the selected algorithm and compares it with the value entered by the user in the "Check Value" field. The check_hash method is called when the button is clicked. This method first gets the file path and selected algorithm from the corresponding variables, and then reads the file in binary mode and computes the hash using the hashlib module. The computed hash value is then set as the value of the self.hash_value variable, and compared with the value entered by the user. If the values match, the self.hash_matched variable is set to True, otherwise it is set to False. The background color of the self.result_entry field is set to green if the hash values match, or red if they do not match. If no value was entered in the "Check Value" field, the self.hash_matched variable is set to an empty string and the background color of the self.result_entry field is set to white.

python

def check_hash(self):
    file_path = self.file_path.get()
    hash_algorithm = self.hash_algorithm.get()
    hash_function = getattr(hashlib, hash_algorithm)

    try:
        with open(file_path, 'rb') as f:
            hash_value = hash_function(f.read()).hexdigest()
            self.hash_value.set(hash_value)

            check_value = self.check_value.get()
            if check_value:
                self.hash_matched.set(hash_value == check_value)

                if self.hash_matched.get():
                    self.result_entry.config(bg='green')
                else:
                    self.result_entry.config(bg='red')
            else:
                self.hash_matched.set("")
                self.result_entry.config(bg='white')
    except FileNotFoundError:
        self.hash_value.set("File not found")
        self.result_entry.config(bg='white')

