import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from encrypt import encrypt_image
from decrypt import decrypt_image

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Image Steganography")
        self.root.geometry("600x400")
        self.root.resizable(True, True)

        self.selected_document_path = None  # Store selected document path
        self.selected_image_path = None  # Store selected image path

        # === Encryption Section ===
        self.enc_label = tk.Label(root, text="Encryption", font=("Arial", 10, "bold"))
        self.enc_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.dec_label = tk.Label(root, text="Decryption", font=("Arial", 10, "bold"))
        self.dec_label.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        # Dropdown for file selection
        self.file_type_label = tk.Label(root, text="Select Document:")
        self.file_type_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.file_type_dropdown = ttk.Combobox(root, values=["txt", "pdf", "docx"], state="readonly")
        self.file_type_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.file_type_dropdown.bind("<<ComboboxSelected>>", self.select_document)  # Bind event

        # Image selection button
        self.image_button = tk.Button(root, text="Select Image", command=self.select_image)
        self.image_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # Password entry for encryption
        self.enc_password_label = tk.Label(root, text="Enter the password:")
        self.enc_password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.enc_password_entry = tk.Entry(root, show="*")
        self.enc_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.toggle_enc_password = tk.Button(root, text="👁", command=lambda: self.toggle_password(self.enc_password_entry))
        self.toggle_enc_password.grid(row=3, column=2, padx=5, pady=5, sticky="w")

        # Encryption Button
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        # Password entry for decryption
        self.dec_password_label = tk.Label(root, text="Enter the password:")
        self.dec_password_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        self.dec_password_entry = tk.Entry(root, show="*")
        self.dec_password_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        self.toggle_dec_password = tk.Button(root, text="👁", command=lambda: self.toggle_password(self.dec_password_entry))
        self.toggle_dec_password.grid(row=1, column=4, padx=5, pady=5, sticky="w")

        # Decryption Button
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=2, column=2, columnspan=2, padx=5, pady=5)

    def toggle_password(self, entry):
        """Toggle password visibility."""
        if entry.cget("show") == "*":
            entry.config(show="")
        else:
            entry.config(show="*")

    def select_document(self, event):
        """Opens file dialog when the user selects a file type from the dropdown."""
        file_type = self.file_type_dropdown.get()
        file_types = {
            "txt": ("Text Files", "*.txt"),
            "pdf": ("PDF Files", "*.pdf"),
            "docx": ("Word Documents", "*.docx")
        }

        if file_type not in file_types:
            messagebox.showerror("Error", "Please select a valid document type first!")
            return

        document_path = filedialog.askopenfilename(title="Select Document", filetypes=[file_types[file_type]])
        if document_path:
            self.selected_document_path = document_path
            messagebox.showinfo("File Selected", f"Selected Document: {document_path}")

    def select_image(self):
        """Opens file dialog for selecting an image."""
        if not self.selected_document_path:
            messagebox.showerror("Error", "Please select a document first!")
            return

        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("ALL Images", "*.png;*.jpg"),("PNG Images", "*.png"),("JPG Images", "*.jpg")])
        if image_path:
            self.selected_image_path = image_path
            messagebox.showinfo("Image Selected", f"Selected Image: {image_path}")

    def encrypt(self):
        """Handles encryption process."""
        password = self.enc_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required for encryption!")
            return

        if not self.selected_document_path:
            messagebox.showerror("Error", "Please select a document first!")
            return
        
        if not self.selected_image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return

        file_name = simpledialog.askstring("Output File Name", "Enter the name for the encrypted file (without extension):")
        if not file_name:
            return

        output_path = filedialog.asksaveasfilename(
            initialfile=file_name,
            defaultextension=".png",
            title="Save Encrypted File",
            filetypes=[("PNG Images", "*.png")]
        )

        if not output_path:
            return

        try:
            encrypt_image(self.selected_image_path, self.selected_document_path, password, output_path)
            messagebox.showinfo("Success", f"File saved successfully!\n\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        """Handles decryption process."""
        password = self.dec_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required for decryption!")
            return

        image_path = filedialog.askopenfilename(title="Select Encoded Image", filetypes=[("PNG Images", "*.png")])
        if not image_path:
            return

        try:
            result = decrypt_image(image_path, password)
            messagebox.showinfo("Decoded Message", result)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
