# Appendix 2026-08-07 — quyền truy cập live demo

Giao diện đã được deploy tại <https://sentinel-benchmarkjava.streamlit.app/> từ branch `main`, entrypoint `app/streamlit_app.py`. Tuy nhiên, kiểm tra bằng HTTP client không có session ngày 2026-08-07 bị redirect tới Streamlit `/login`. Vì vậy deployment tồn tại nhưng **chưa đạt điều kiện public mentor demo**.

Việc cần làm trong Streamlit Community Cloud: mở app settings, bật public sharing, sau đó kiểm tra lại bằng cửa sổ ẩn danh. Appendix này bổ sung trạng thái truy cập; báo cáo chính Week 2 không bị sửa sau khi khóa checksum.
