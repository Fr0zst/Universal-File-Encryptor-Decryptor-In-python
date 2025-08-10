#!/usr/bin/env python3
"""
Universal File Encryptor/Decryptor
A tool to encrypt and decrypt any type of file using AES encryption.
"""

import os
import sys
import argparse
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
import time
import random
import threading

def glitch_text_effect():
    """Display glitchy text effect while password is being entered."""
    glitch_chars = ['█', '▓', '▒', '░', '▀', '▄', '▌', '▐', '■', '▪', '▫', '◆', '◇', '○', '●']
    glitch_messages = [
        "ACCESSING SECURE VAULT...",
        "BYPASSING FIREWALLS...",
        "DECRYPTING PROTOCOLS...", 
        "VALIDATING CREDENTIALS...",
        "ESTABLISHING SECURE LINK...",
        "AUTHENTICATING USER...",
        "LOADING ENCRYPTION KEYS...",
        "SECURING CONNECTION..."
    ]
    
    class GlitchController:
        def __init__(self):
            self.running = True
            
        def stop(self):
            self.running = False
    
    controller = GlitchController()
    
    def animate():
        while controller.running:
            # Random glitch message
            msg = random.choice(glitch_messages)
            glitched_msg = ""
            
            # Randomly replace some characters with glitch chars
            for char in msg:
                if random.random() < 0.15:  # 15% chance to glitch
                    glitched_msg += random.choice(glitch_chars)
                else:
                    glitched_msg += char
            
            print(f"\r{glitched_msg}", end="", flush=True)
            time.sleep(0.1)
    
    # Start the animation thread
    thread = threading.Thread(target=animate, daemon=True)
    thread.start()
    
    return controller.stop

def secure_password_input(prompt="Enter password: ", confirm=False):
    """Get password input with glitch effect."""
    print()
    
    # Start glitch effect
    print(prompt)
    stop_glitch = glitch_text_effect()
    
    try:
        # Get the actual password (hidden)
        password = getpass.getpass("")
        
        # Stop glitch effect
        stop_glitch()
        print("\r" + " " * 50 + "\r", end="")  # Clear glitch line
        
        if confirm:
            print("Confirm password:")
            stop_glitch2 = glitch_text_effect()
            confirm_password = getpass.getpass("")
            stop_glitch2()
            print("\r" + " " * 50 + "\r", end="")  # Clear glitch line
            
            if password != confirm_password:
                print("❌ PASSWORDS DO NOT MATCH")
                return None
        
        print("✅ PASSWORD ACCEPTED")
        return password
        
    except KeyboardInterrupt:
        stop_glitch()
        print("\n❌ CANCELLED")
        return None

def lock_animation(action="encrypt"):
    """Display a clean lock animation for encrypt/decrypt operations."""
    # Clear the line first
    print()
    
    if action == "encrypt":
        frames = [
            "[ ]  Processing...",
            "[=]  Encrypting...", 
            "[#]  Securing...  ",
            "[█]  Finalizing...",
            "[█]  Complete!    "
        ]
        title = "ENCRYPTING FILE"
    else:  # decrypt
        frames = [
            "[█]  Processing...",
            "[#]  Decrypting...",
            "[=]  Restoring... ",
            "[ ]  Finalizing...",
            "[ ]  Complete!    "
        ]
        title = "DECRYPTING FILE"
    
    # Clean title
    print(f"┌─ {title} ─┐")
    
    # Animation
    for frame in frames:
        print(f"│ {frame} │", end="", flush=True)
        time.sleep(0.4)
        print("\r" + " " * 25 + "\r", end="", flush=True)  # Clear line
    
    # Final message
    status = "ENCRYPTED" if action == "encrypt" else "DECRYPTED"
    print(f"│ ✓ {status}      │")
    print("└─────────────────┘")
    print()

class UniversalFileEncryptor:
    def __init__(self, password: str):
        """Initialize the encryptor with a password."""
        self.password = password.encode()
        
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> bool:
        """Encrypt any type of file."""
        file_path = Path(file_path)
        
        # Check if file exists
        if not file_path.exists():
            print(f"Error: File '{file_path}' does not exist.")
            print("Please check:")
            print("- The file path is correct")
            print("- You have permission to access the file")
            print("- The file hasn't been moved or deleted")
            return False
        
        # Check if it's a directory
        if file_path.is_dir():
            print(f"Error: '{file_path}' is a directory, not a file.")
            print("Please specify a file to encrypt.")
            return False
        
        try:
            # Read the original file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            print(f"File size: {len(file_data):,} bytes")
            
            # Generate a random salt
            salt = os.urandom(16)
            
            # Derive key from password
            key = self._derive_key(salt)
            fernet = Fernet(key)
            
            # Encrypt the file data
            encrypted_data = fernet.encrypt(file_data)
            
            # Determine output path
            if output_path is None:
                # Default to current user's Downloads folder
                downloads_path = Path.home() / "Downloads"
                if downloads_path.exists():
                    output_path = downloads_path / f"{file_path.name}.enc"
                else:
                    # Fallback to same directory as original file
                    output_path = file_path.with_suffix(file_path.suffix + '.enc')
                    print("Note: Downloads folder not found, saving to original file location.")
            else:
                output_path = Path(output_path)
            
            # Write encrypted file with salt prepended
            with open(output_path, 'wb') as f:
                f.write(salt + encrypted_data)
            
            # Show lock animation
            lock_animation("encrypt")
            
            print(f"Successfully encrypted {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            print(f"Error encrypting file: {e}")
            return False
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str = None) -> bool:
        """Decrypt an encrypted file."""
        encrypted_file_path = Path(encrypted_file_path)
        
        # Check if encrypted file exists
        if not encrypted_file_path.exists():
            print(f"Error: File {encrypted_file_path} does not exist.")
            return False
        
        try:
            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content = f.read()
            
            # Extract salt (first 16 bytes) and encrypted data
            if len(encrypted_content) < 16:
                print("Error: Invalid encrypted file format.")
                return False
                
            salt = encrypted_content[:16]
            encrypted_data = encrypted_content[16:]
            
            # Derive key from password
            key = self._derive_key(salt)
            fernet = Fernet(key)
            
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Determine output path
            if output_path is None:
                if encrypted_file_path.suffix == '.enc':
                    # Try to restore original filename by removing .enc
                    output_path = encrypted_file_path.with_suffix('')
                else:
                    output_path = encrypted_file_path.with_suffix('.decrypted')
            else:
                output_path = Path(output_path)
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Show unlock animation
            lock_animation("decrypt")
            
            print(f"Successfully decrypted {encrypted_file_path} -> {output_path}")
            return True
            
        except Exception as e:
            print(f"Error decrypting file: {e}")
            print("This might be due to an incorrect password or corrupted file.")
            return False

def interactive_menu():
    """Interactive menu for file encryption/decryption."""
    print("\n" * 2)
    print("█▀▀ █▀█ █▀█ █▄▀ █▀▀ █▀▄")
    print("█▄▄ █▄█ █▄█ █ █ ██▄ █▄▀")
    print("=" * 50)
    print("     Universal File Encryptor/Decryptor")
    print("           🔒 Files Get Protected 🔒")
    print("=" * 50)
    
    while True:
        try:
            # Get file path
            print("\nEnter the path to your file:")
            file_path = input("File path: ").strip()
            
            # Remove surrounding quotes if present (common copy-paste issue)
            if file_path.startswith('"') and file_path.endswith('"'):
                file_path = file_path[1:-1]
            elif file_path.startswith("'") and file_path.endswith("'"):
                file_path = file_path[1:-1]
            
            if not file_path:
                print("Please enter a valid file path.")
                continue
            
            # Show menu options
            print("\nWhat would you like to do?")
            print("1. Encrypt the file")
            print("2. Decrypt the file")
            print("3. Exit program")
            
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '3':
                print("Goodbye!")
                break
            elif choice not in ['1', '2']:
                print("Invalid choice. Please enter 1, 2, or 3.")
                continue
            
            # Get password based on action
            if choice == '1':  # Encrypt
                password = secure_password_input("🔒 Enter encryption password:", confirm=True)
                if password is None:
                    continue
            else:  # Decrypt
                password = secure_password_input("🔓 Enter decryption password:")
                if password is None:
                    continue
            
            if not password:
                print("Error: Password cannot be empty.")
                continue
            
            # Create encryptor instance
            encryptor = UniversalFileEncryptor(password)
            
            # Ask for custom output path (optional)
            custom_output = input("\nCustom output path (press Enter to use default): ").strip()
            output_path = custom_output if custom_output else None
            
            # Perform the action
            print(f"\n{'Encrypting' if choice == '1' else 'Decrypting'} file...")
            
            if choice == '1':
                success = encryptor.encrypt_file(file_path, output_path)
            else:
                success = encryptor.decrypt_file(file_path, output_path)
            
            if success:
                print("Operation completed successfully!")
            else:
                print("Operation failed. Please check the error message above.")
                
            # Ask if user wants to continue
            continue_choice = input("\nWould you like to process another file? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes']:
                print("Goodbye!")
                break
                
        except KeyboardInterrupt:
            print("\n\nProgram interrupted by user. Goodbye!")
            break
        except Exception as e:
            print(f"\nUnexpected error: {e}")
            continue_choice = input("Would you like to try again? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes']:
                break

def main():
    # Check if command line arguments are provided
    if len(sys.argv) > 1:
        # Use command line interface
        parser = argparse.ArgumentParser(description='Encrypt and decrypt any type of file')
        parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
        parser.add_argument('file', help='Path to the file to encrypt/decrypt')
        parser.add_argument('-o', '--output', help='Output file path (optional)')
        parser.add_argument('-p', '--password', help='Encryption password (will prompt if not provided)')
        
        args = parser.parse_args()
        
        # Get password
        if args.password:
            password = args.password
        else:
            if args.action == 'encrypt':
                password = secure_password_input("🔒 Enter encryption password:", confirm=True)
                if password is None:
                    print("Error: Password input cancelled.")
                    sys.exit(1)
            else:
                password = secure_password_input("🔓 Enter decryption password:")
                if password is None:
                    print("Error: Password input cancelled.")
                    sys.exit(1)
        
        if not password:
            print("Error: Password cannot be empty.")
            sys.exit(1)
        
        # Create encryptor instance
        encryptor = UniversalFileEncryptor(password)
        
        # Perform the requested action
        if args.action == 'encrypt':
            success = encryptor.encrypt_file(args.file, args.output)
        else:
            success = encryptor.decrypt_file(args.file, args.output)
        
        sys.exit(0 if success else 1)
    else:
        # Use interactive menu
        interactive_menu()

if __name__ == '__main__':
    main()