from PIL import Image
import stepic
import base64
import hashlib
from cryptography.fernet import Fernet
import PyPDF2
import docx

def generate_key(password):
    """Generate a 32-byte encryption key from the user-provided password."""
    hashed = hashlib.sha256(password.encode()).digest()  # Hash password
    key = base64.urlsafe_b64encode(hashed)  # Convert to base64
    return Fernet(key)  # Return a valid Fernet object
def extract_text_from_document(file_path):
    """Extract text from TXT, PDF, or DOCX files."""
    if file_path.endswith(".txt"):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    elif file_path.endswith(".pdf"):
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            return " ".join([page.extract_text() for page in reader.pages])
    elif file_path.endswith(".docx"):
        doc = docx.Document(file_path)
        return " ".join([para.text for para in doc.paragraphs])
    else:
        raise ValueError("Unsupported file type.")

def encrypt_image(image_path, document_path, password, output_path):
    """Encrypt and encode text from a document into an image."""
    try:
        secret_data = extract_text_from_document(document_path)
        key = generate_key(password)
        encrypted_data = key.encrypt(secret_data.encode())

        image = Image.open(image_path)
        encoded_image = stepic.encode(image, encrypted_data)

        # DEBUG: Print output path
        print(f"Saving encoded image to: {output_path}")

        encoded_image.save(output_path, format='PNG')

        return f"Data successfully hidden in {output_path}"
    
    except Exception as e:
        print(f"Error: {e}")  # Print exact error for debugging
        return f"Error: {e}"
