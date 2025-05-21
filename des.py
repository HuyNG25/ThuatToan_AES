from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

BLOCK_SIZE = 16
# IV cố định phải khớp với IV được sử dụng trong quá trình mã hóa.
FIXED_IV = b'0123456789abcdef'

def get_key(password: str) -> bytes:
    """
    Tạo khóa AES 128-bit (16 bytes) từ mật khẩu.
    """
    # LPad bằng null byte nếu password ngắn hơn 16, hoặc cắt bớt nếu dài hơn
    return password.encode('utf-8').ljust(16, b'\0')[:16]

def decrypt_base64_data(b64_data: str, password: str) -> bytes:
    """
    Giải mã chuỗi Base64 đã mã hóa.
    Dự kiến chuỗi Base64 chứa IV nối vào đầu ciphertext.
    """
    try:
        # Giải mã Base64 thành dữ liệu nhị phân (dự kiến là IV + ciphertext)
        data_binary = base64.b64decode(b64_data)
    except Exception as e:
        raise ValueError(f"Dữ liệu Base64 không hợp lệ hoặc bị hỏng: {e}")

    # Kiểm tra độ dài dữ liệu để đảm bảo có đủ IV và ít nhất 1 khối mã hóa
    if len(data_binary) < BLOCK_SIZE:
        raise ValueError("Dữ liệu mã hóa không đủ độ dài để chứa IV và ciphertext.")

    # Tách IV và ciphertext
    # IV sẽ là BLOCK_SIZE byte đầu tiên
    retrieved_iv = data_binary[:BLOCK_SIZE]
    ciphertext_only = data_binary[BLOCK_SIZE:]

    key = get_key(password)

    # Quan trọng: Dùng FIXED_IV để khởi tạo cipher.
    # Mặc dù chúng ta đọc `retrieved_iv` từ file, nhưng vì cam kết sử dụng `FIXED_IV`
    # cho ứng dụng này, chúng ta sẽ luôn sử dụng nó ở đây để đảm bảo khớp.
    # Một kiểm tra `if retrieved_iv != FIXED_IV: raise ValueError("IV không khớp")`
    # có thể hữu ích cho debug nhưng sẽ gây lỗi nếu file được mã hóa với IV khác.
    cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)
    
    try:
        # Giải mã phần ciphertext (đã bỏ IV)
        plaintext = unpad(cipher.decrypt(ciphertext_only), BLOCK_SIZE)
    except (ValueError, KeyError) as e:
        # Bắt lỗi padding nếu mật khẩu sai hoặc dữ liệu bị hỏng
        raise ValueError(f"Mật khẩu sai hoặc dữ liệu file không hợp lệ: {e}")
    except Exception as e:
        raise Exception(f"Lỗi giải mã không xác định: {e}")

    return plaintext