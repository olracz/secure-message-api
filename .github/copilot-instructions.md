# Secure Message API - AI Agent Instructions

## Architecture Overview
- **Flask REST API**: Single app in `api/app.py` with `/api/encrypt` and `/api/decrypt` endpoints for AES-GCM symmetric encryption
- **Modular Crypto Package**: `crypto/` contains `aesgcm/` (implemented) and `rsa/` (stubbed) submodules, plus `utils/` for shared functions
- **Data Flow**: API accepts JSON payloads, processes through crypto modules, returns JSON responses with base64-encoded results
- **Key Management**: AES key loaded from `.env` (`AES_GCM_KEY`), RSA keys in `keys/` directory (PEM files)
- **Why Modular**: Separates encryption algorithms for future hybrid encryption (RSA for key exchange + AES for data)

## Key Patterns
- **Base64 Encoding**: Always use `crypto.utils.b64_encode()` and `b64_decode()` for URL-safe base64 without padding (strips '=' on encode, adds padding on decode)
- **Nonce Generation**: Use `crypto.utils.generate_nonce(length=12)` returning `secrets.token_bytes(12)` for AES-GCM
- **Environment Loading**: Call `dotenv.load_dotenv()` at module start for key access via `os.getenv()`
- **Logging**: Centralized in `api.log` with format `'%(asctime)s - %(levelname)s - %(message)s'`, log warnings for missing fields
- **API Responses**: Encrypt returns `{"encrypted": {"ciphertext": str, "nonce": str}}`, decrypt returns `{"decrypted": str}`

## Developer Workflows
- **Run API**: `python api/app.py` (starts Flask in debug mode on localhost:5000)
- **Run Tests**: `python tests/test_encryption.py` (currently imports incorrectly; use `from crypto.aesgcm import encrypt, decrypt`)
- **Install Dependencies**: `pip install -r requirements.txt` (includes Flask, cryptography, python-dotenv)
- **Key Generation**: RSA keys in `keys/`; AES key pre-set in `.env` as base64-encoded 256-bit key

## Project Conventions
- **Import Style**: Within crypto package use relative imports (e.g., `from .utils import b64_encode`); from outside use absolute (e.g., `from crypto.aesgcm import encrypt`)
- **Error Handling**: API endpoints return JSON `{"error": "message"}` with 400 status for missing/invalid inputs
- **File Structure**: Each crypto algorithm in its own subdirectory with separate encrypt/decrypt files
- **Testing**: Simple class-based tests run via `if __name__ == "__main__"` (no framework like pytest)</content>
<parameter name="filePath">c:\Users\user\Desktop\secure-message-api\.github\copilot-instructions.md