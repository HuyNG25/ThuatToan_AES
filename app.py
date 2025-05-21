from flask import Flask, render_template, request, send_file, jsonify, session, redirect, url_for, flash
import io
import os # Import os để tạo secret key an toàn hơn

# Import các hàm mã hóa và giải mã từ các file riêng
from enc import encrypt_data_to_base64
from des import decrypt_base64_data

app = Flask(__name__)
# RẤT QUAN TRỌNG: Thay thế bằng một key ngẫu nhiên mạnh mẽ cho session
# Sử dụng os.urandom để tạo key ngẫu nhiên an toàn (cho môi trường production, cần quản lý tốt hơn)
app.secret_key = os.urandom(24) # Tạo một secret key 24 byte (192 bit) ngẫu nhiên

# --- Route Trang chủ ---
@app.route('/')
def home():
    return render_template('home.html')

# --- Route Trang Mã hóa ---
@app.route('/encrypt_tool')
def encrypt_tool():
    return render_template('encrypt_page.html')

# --- Route Trang Giải mã ---
@app.route('/decrypt_tool')
def decrypt_tool():
    return render_template('decrypt_page.html')

# --- API Endpoint Mã hóa ---
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    file = request.files.get('file')
    password = request.form.get('password')

    if not file or not password:
        return jsonify({'success': False, 'error': 'Vui lòng chọn file và nhập mật khẩu.'}), 400

    data = file.read() # Đọc dữ liệu thô từ file

    try:
        # Gọi hàm mã hóa từ enc.py. Hàm này sẽ trả về chuỗi Base64
        # và dữ liệu nhị phân (IV + ciphertext) để lưu vào session.
        b64_ciphertext, ciphertext_with_iv_binary = encrypt_data_to_base64(data, password)

        # Lưu dữ liệu thô (IV + ciphertext nhị phân) vào session để tải xuống.
        # Dữ liệu này sẽ được tải xuống dưới dạng văn bản Base64 trong Data.txt.
        # Vì file được tải xuống là văn bản, chúng ta lưu chuỗi Base64 vào session.
        session['file_data_to_download'] = b64_ciphertext.encode('utf-8') # Lưu dạng bytes
        session['download_type'] = 'encrypted'
        session['original_filename'] = 'Data.txt' # Đặt tên file tải xuống cố định

        return jsonify({
            'success': True,
            'result': b64_ciphertext # Gửi chuỗi Base64 về client để hiển thị
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi mã hóa: {str(e)}'}), 500


# --- API Endpoint Giải mã ---
@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    file = request.files.get('file')
    password = request.form.get('password')

    if not file or not password:
        return jsonify({'success': False, 'error': 'Vui lòng chọn file và nhập mật khẩu.'}), 400

    # Đọc nội dung file (đây là chuỗi Base64 từ file Data.txt đã mã hóa)
    try:
        b64_data_from_file = file.read().decode('utf-8')
    except Exception:
        return jsonify({'success': False, 'error': 'Dữ liệu file không phải định dạng văn bản UTF-8 hợp lệ hoặc file bị hỏng.'}), 400

    try:
        # Gọi hàm giải mã từ des.py. Hàm này sẽ trả về dữ liệu plaintext nhị phân.
        plaintext_binary = decrypt_base64_data(b64_data_from_file, password)

        # Lưu dữ liệu thô (đã giải mã) vào session để tải xuống
        session['file_data_to_download'] = plaintext_binary
        session['download_type'] = 'decrypted'
        session['original_filename'] = 'Data.txt' # Đặt tên file tải xuống cố định

        # Cố gắng decode plaintext thành utf-8 để hiển thị trên web.
        # Nếu không phải văn bản, sẽ hiển thị thông báo.
        try:
            text_plain = plaintext_binary.decode('utf-8')
        except UnicodeDecodeError:
            text_plain = "[File không phải văn bản hoặc có mã hóa khác. Nội dung có thể hiển thị không chính xác.]"

        return jsonify({
            'success': True,
            'result': text_plain
        })
    except (ValueError, KeyError) as e:
        # Bắt các lỗi cụ thể từ PyCryptodome (ví dụ: lỗi padding) hoặc lỗi logic của chúng ta
        return jsonify({'success': False, 'error': f'Mật khẩu sai hoặc file không hợp lệ: {str(e)}. Vui lòng kiểm tra lại mật khẩu hoặc đảm bảo file được mã hóa đúng.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi giải mã không xác định: {str(e)}'}), 500

# --- API Endpoint Tải xuống ---
@app.route('/download')
def download():
    file_data = session.pop('file_data_to_download', None)
    download_type = session.pop('download_type', None)
    original_filename = session.pop('original_filename', 'Data.txt') # Mặc định là Data.txt

    if file_data is None:
        flash("Không có dữ liệu để tải xuống. Vui lòng thực hiện mã hóa/giải mã trước.")
        return redirect(url_for('home'))

    # Cả file mã hóa và giải mã đều được yêu cầu lưu và tải xuống dưới dạng văn bản (text/plain)
    # và tên file luôn là Data.txt.
    download_name = original_filename # Luôn là 'Data.txt'
    mimetype = 'text/plain' # Luôn là text/plain

    return send_file(
        io.BytesIO(file_data),
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name
    )

@app.route('/exit')
def exit_page():
    return '''
    <script>
      alert("Đang đóng trang web...");
      window.close();
      if(!window.closed) {
        alert("Không thể tự động đóng trình duyệt do hạn chế trình duyệt. Vui lòng đóng tab thủ công.");
      }
    </script>
    '''

if __name__ == '__main__':
    app.run(debug=True)