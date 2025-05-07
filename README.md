# Hệ thống Phát hiện Xâm nhập Thời gian Thực (Real-time IDS)
## Giới thiệu
Hệ thống triển khai một hệ thống phát hiện xâm nhập (IDS) thời gian thực sử dụng thư viện nfstream để phân tích lưu lượng mạng, trích xuất đặc trưng, và dự đoán các hành vi bất thường (tấn công hoặc bình thường) bằng mô hình học máy. Kết quả được lưu vào tệp CSV và hiển thị qua giao diện web sử dụng Flask.
### Tính năng chính
- Bắt và phân tích lưu lượng mạng theo thời gian thực bằng nfstream.
- Trích xuất đặc trưng từ luồng mạng theo định dạng CICIDS2017.
- Dự đoán hành vi mạng (bình thường hoặc tấn công) bằng mô hình học máy.
- Lưu kết quả vào tệp CSV (predictions.csv) và hiển thị qua giao diện web.
- Hỗ trợ giám sát từ xa thông qua giao diện web Flask.
## Cấu trúc thư mục
- **models/**: Thư mục chứa các tệp mô hình học máy đã được huấn luyện.  
  - **best_binary_model.pkl**: Mô hình phân loại nhị phân.  
  - **scaler.pkl**: Bộ chuẩn hóa đặc trưng (StandardScaler).  
  - **label_encoder_binary.pkl**: Bộ mã hóa nhãn cho phân loại nhị phân (LabelEncoder).  
- **templates/**: Thư mục chứa giao diện web.  
  - **index.html**: Tệp HTML hiển thị kết quả dự đoán.  
- **application.py**: Mã nguồn chính, xử lý gói tin, dự đoán, và hiển thị kết quả.  
- **predictions.csv**: Tệp lưu kết quả dự đoán (IP nguồn, IP đích, nhãn, xác suất, thời gian).  
## Yêu cầu hệ thống
- Hệ điều hành: Ubuntu (hoặc các hệ điều hành Linux khác).
- Python 3.6 trở lên.
- Các thư viện Python:
  - nfstream
  - pandas
  - numpy
  - joblib
  - scikit-learn
  - flask
## Hướng dẫn cài đặt

### 1. Cài đặt Python và pip
- Đảm bảo Python 3 và pip đã được cài đặt trên hệ thống của bạn. Nếu chưa, chạy các lệnh sau trên Ubuntu:
```bash
sudo apt update
sudo apt install python3 python3-pip
```
### 2. Cài đặt các thư viện cần thiết
- Cài đặt các thư viện Python bằng lệnh:
```bash
pip3 install nfstream pandas numpy joblib scikit-learn flask
```
### 3. Cấu hình giao diện mạng
- Mở tệp application.py và cập nhật biến INTERFACE với giao diện mạng của bạn (ví dụ: eth0, wlan0).
```bash
INTERFACE = "ens33"  # Thay "ens33" bằng giao diện của bạn
```
- Để kiểm tra giao diện mạng, sử dụng lệnh:
```bash
ifconfig
```
### 4. Đảm bảo thư mục models có sẵn
- Đặt các tệp best_binary_model.pkl, scaler.pkl, và label_encoder_binary.pkl vào thư mục models/.
- Nếu bạn chưa có các tệp này, cần huấn luyện mô hình trên bộ dữ liệu (ví dụ: CICIDS2017) và lưu bằng joblib.

## Hướng dẫn chạy hệ thống
### 1. Chạy chương trình
- Trong thư mục chứa application.py, chạy lệnh:
```bash
python3 application.py
```
- Chương trình sẽ:
  - Bắt gói tin từ giao diện mạng đã cấu hình.
  - Trích xuất đặc trưng, dự đoán, và lưu kết quả vào predictions.csv.
  - Khởi động giao diện web Flask tại http://localhost:5001.
### 2. Truy cập giao diện web
- Mở trình duyệt và truy cập:
```bash
http://localhost:5001
```
- Giao diện sẽ hiển thị các luồng mạng đã xử lý, bao gồm IP nguồn, IP đích, cổng, nhãn dự đoán, và xác suất.
## Cách sử dụng
- **Giám sát thời gian thực:** Hệ thống sẽ liên tục bắt gói tin và dự đoán hành vi mạng. Kết quả được cập nhật trên giao diện web.
- **Phân tích hậu kỳ:** Kiểm tra tệp predictions.csv để xem lịch sử các luồng mạng đã xử lý.
- **Tùy chỉnh:**
  - Thay đổi thời gian xử lý luồng bằng cách chỉnh sửa WINDOW_DURATION trong application.py.
  - Cập nhật mô hình học máy trong thư mục models nếu cần cải thiện độ chính xác.
## Lưu ý
- Đảm bảo bạn có quyền truy cập vào giao diện mạng (có thể cần chạy với sudo):
```bash
sudo python3 application.py
```
- Với lưu lượng mạng lớn, hệ thống có thể tiêu tốn CPU/memory. Cân nhắc điều chỉnh WINDOW_DURATION hoặc giới hạn lưu lượng.
- Tệp predictions.csv được ghi ở chế độ thêm, vì vậy kích thước tệp sẽ tăng theo thời gian. Có thể cần xóa hoặc lưu trữ định kỳ.
## Tác giả
- **Công Quân**  
  Email: 22521190@gm.uit.edu.vn  
- **Quốc Minh**  
  Email: 22520855@gm.uit.edu.vn
  ## Giấy phép
Dự án này được cấp phép theo [MIT License](https://opensource.org/licenses/MIT).
