# VulnLab Study V5 — nguồn và cách cập nhật

V5 là website học Vulnerability Management theo hướng phòng thủ. **Một CVE = một hồ sơ**, không tách thành nhiều danh mục CVE lặp nhau. Mỗi hồ sơ có các tab: Đọc hiểu, Tác động giả định, Triage/evidence, Fix + Verify và Luyện tập.

## Mở thử ngay (Windows)

- Nếu chỉ thử giao diện: tải **VulnLab-V5-Open.html** và mở bằng Chrome/Edge. Không cần cài Python, Node, extension hay tài khoản.
- File HTML một khối **không tự tải NVD/EPSS định kỳ**. Nó có thể bấm tải CISA KEV trực tiếp bằng trình duyệt nếu mạng truy cập được CISA GitHub mirror. Kết quả tải trong phiên duyệt không lưu vĩnh viễn vào file.
- Muốn public/cập nhật hàng ngày: dùng cả thư mục source trong ZIP, đưa lên GitHub, deploy Vercel và bật GitHub Actions.

## V5 thực sự có bao nhiêu bài?

- Kho offline: **30 mã CVE khác nhau**, trong đó **5 bài học chuyên sâu** (lồng trong kho, không phải cộng thêm 5).
- **6 case biên soạn** với các bước ra quyết định và bằng chứng mô phỏng; **14 câu quiz kỹ thuật do người viết**.
- **Mọi CVE**, kể cả CVE mới được đồng bộ, đều mở được mục phân tích metadata, **case triage 3 bước theo mẫu** và **quiz triage 4 câu theo metadata**. Đây không phải mô phỏng attack chain đã xác nhận của từng CVE.
- CVE mới KHÔNG tự có bài exploit/incident cụ thể. Case và quiz chuyên sâu chỉ tăng khi cập nhật bộ dữ liệu biên soạn/kiểm chứng. Không giới hạn kỹ thuật số case hay quiz.

### Thuật ngữ nguồn

- **CISA KEV**: có bằng chứng khai thác trong thực tế ở đâu đó; không chứng minh một asset của công ty đã bị xâm nhập.
- **CVSS (NVD/vendor)**: mức độ nghiêm trọng theo phương pháp đánh giá; không bao hàm tất cả ngữ cảnh riêng của tài sản.
- **EPSS (FIRST)**: xác suất khai thác dự báo, không phải độ nghiêm trọng và không phải chứng cứ đã bị khai thác.
- **Bài chuyên sâu**: giải thích và ví dụ được biên soạn, có link hãng/CISA/NVD. Log và tổ chức trong các case là giả định trừ khi có ghi rõ.

## Công khai trên Vercel + tự đồng bộ

1. Giải nén **VulnLab-V5-Source.zip**. Upload **nội dung** thư mục `vulnlab-v5` lên GitHub, ở **root** của repository để `index.html` nằm tại root.
2. Trong [Vercel](https://vercel.com/new), chọn **Add New Project** > import đúng GitHub repository. Với website tĩnh, Vercel thường nhận cấu hình mặc định; nếu cần, Framework preset = Other, không cần Build command.
3. Public site, mở đường dẫn `https://<ten-project>.vercel.app/`.
4. Trong GitHub repository > **Actions** > workflow **Update VulnLab CVE feeds** > **Run workflow**. Workflow cũng đã lên lịch hằng ngày lúc 03:19 UTC (10:19 giờ Việt Nam; GitHub có thể chạy trễ).
5. Nếu deploy Vercel không chạy lại khi bot GitHub Actions commit, tạo **Vercel Deploy Hook** và đặt URL đó vào GitHub repo > Settings > Secrets and variables > Actions > secret `VERCEL_DEPLOY_HOOK` để workflow kích hoạt build. Giữ URL này bí mật.
6. Tùy chọn: NVD API key lưu ở repo secret `NVD_API_KEY`, **không đưa vào HTML/JS**.
7. Xem file `data/feed-data.json` sau lần chạy để kiểm tra ngày `updated`, các trường `status.kev/nvd/epss` và số bản ghi. Lỗi nguồn không được hiển thị như đồng bộ thành công.

## Cách hoạt động của feed

`python scripts/update_feeds.py` sử dụng Python standard library:

- Lấy CISA KEV từ official CISA-hosted JSON / `cisagov/kev-data` mirror.
- Lấy tối đa **500 CVE mới** trong cửa sổ **7 ngày** bằng NVD CVE API 2.0; không phải bản sao đầy đủ NVD.
- Lấy EPSS cho một tập CVE giới hạn đã chọn từ FIRST.
- Ghi `data/feed-data.js` và `data/feed-data.json`; khi một nguồn lỗi giữ bản hợp lệ gần nhất (nếu có) thay vì biến lỗi thành 0 CVE.
- Frontend gộp tất cả record theo **CVE ID**, hiển thị 1 record duy nhất và các nhãn KEV/NVD/bài chuyên sâu.

Nguồn dữ liệu: [CISA KEV](https://github.com/cisagov/kev-data), [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS](https://api.first.org/epss/).

## Mở rộng bài học thực sự

- `data/curated.js` → `cves[]` cho hồ sơ sâu; `scenarios[]` cho case nhiều bước; `exam[]` cho quiz chuyên môn. Gắn mỗi case/quiz bằng trường `cve` tương ứng; ứng dụng tự liên kết trong hồ sơ.
- `data/reading-queue.js` → các CVE tham khảo offline để có bài đọc khi chưa kết nối feed.
- `data/feed-data.js` → chỉ sinh tự động, **không nên sửa tay**.
- `app.js` → UI và logic tra cứu/điều hướng/chấm điểm; `styles.css` → giao diện.
- Muốn làm lại file HTML offline sau khi sửa source: `python scripts/build_single_file.py`.

**Quy trình soạn nội dung chuẩn:** tìm vendor advisory → phân biệt pre-auth/post-auth, điều kiện môi trường, phiên bản affected/fixed → xác nhận CVSS/KEV/EPSS nếu có → thiết kế bối cảnh asset và log **giả lập có nhãn** → viết 3-5 quyết định kỹ thuật (các phương án sai phải có vẻ hợp lý) → đối chiếu đáp án với advisory/research → xuất bản. Không giả định mọi CVE đều có exploit chain, IOC hoặc fix command đã được xác thực.

## Bảo mật

- Demo chỉ có dữ liệu công khai; không chạy exploit hay quét hệ thống thật.
- LocalStorage lưu tiến độ ở máy người học; không đăng nhập, không đồng bộ giữa máy, có thể xuất JSON.
- Không nhập credentials, IP bí mật, logs chứa thông tin khách hàng vào web public.
- Dữ liệu nguồn công khai có thể thay đổi; với khắc phục production phải đọc advisory vendor và kiểm chứng asset cụ thể.

## Kiểm thử

- `node --check app.js` và `python -m py_compile scripts/*.py`.
- Đã chạy unit/mock JavaScript cho điều hướng các màn chính, CVE sâu, hồ sơ metadata, quiz và case. Trình duyệt tự động trong môi trường tạo file bị chặn điều hướng, nên **chưa khẳng định kiểm thử end-to-end bằng Chrome thật**; nên kiểm thử lại trên máy/hosting của bạn.
