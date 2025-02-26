from PIL import Image
import stepic
import base64
import hashlib
from cryptography.fernet import Fernet

def generate_key(password):
    """Generate a 32-byte encryption key from the user-provided password."""
    hashed = hashlib.sha256(password.encode()).digest()  # Hash password
    key = base64.urlsafe_b64encode(hashed)  # Convert to base64
    return Fernet(key)  # Return a valid Fernet object

def decrypt_image(image_path, password):
    """Extract and decrypt hidden text from an image."""
    try:
        image = Image.open(image_path)
        encrypted_data = stepic.decode(image)

        key = generate_key(password)
        decrypted_data = key.decrypt(encrypted_data).decode()

        return decrypted_data
    except Exception as e:
        return f"Error: {e}"
