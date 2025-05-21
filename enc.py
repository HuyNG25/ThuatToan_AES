from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

BLOCK_SIZE = 16
# IV cố định được sử dụng cho tính nhất quán như yêu cầu của bạn.
# LƯU Ý: Trong thực tế, IV nên được tạo ngẫu nhiên cho mỗi lần mã hóa.
FIXED_IV = b'0123456789abcdef'

def get_key(password: str) -> bytes:
    """
    Tạo khóa AES 128-bit (16 bytes) từ mật khẩu.
    """
    # LPad bằng null byte nếu password ngắn hơn 16, hoặc cắt bớt nếu dài hơn
    return password.encode('utf-8').ljust(16, b'\0')[:16]

def encrypt_data_to_base64(data: bytes, password: str) -> tuple[str, bytes]:
    """
    Mã hóa dữ liệu nhị phân bằng AES-CBC, nối IV vào đầu ciphertext,
    và trả về chuỗi Base64 của (IV + ciphertext) và dữ liệu nhị phân gốc (IV + ciphertext).
    """
    key = get_key(password)
    iv = FIXED_IV

    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Mã hóa dữ liệu và nối IV vào ĐẦU ciphertext.
    # Đây là phần quan trọng để đảm bảo giải mã đúng:
    # dữ liệu được lưu/truyền luôn có cấu trúc IV + ciphertext.
    ciphertext_raw = cipher.encrypt(pad(data, BLOCK_SIZE))
    ciphertext_with_iv = iv + ciphertext_raw

    # Chuyển đổi dữ liệu nhị phân (IV + ciphertext) sang Base64 để hiển thị/lưu dưới dạng văn bản
    b64_ciphertext = base64.b64encode(ciphertext_with_iv).decode('utf-8')

    # Trả về chuỗi Base64 và dữ liệu nhị phân thô (IV + ciphertext)
    return b64_ciphertext, ciphertext_with_iv