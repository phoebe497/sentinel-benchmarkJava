# Kết quả Benchmark & Thử nghiệm Ablation cho Semgrep (20260729T040126Z-semgrep-first100)

*Lưu ý: Semgrep là công cụ SAST tĩnh thuần túy (không dùng LLM), vì vậy không tốn token (Token = 0/N/A).*  
*Tất cả kết quả đều được đối chiếu tự động với Ground Truth của OWASP BenchmarkJava sau khi kết thúc quá trình quét.*

### Bảng kết quả so sánh các biến thể của Semgrep

| Biến thể (Variant) | Số cảnh báo | TP | FP | FN | TN | Precision | Recall | F1-Score | Thời gian (giây) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **S0-semgrep-java** | 75 | 43 | 4 | 32 | 21 | 91.49% | 57.33% | 70.49% | 13.03s |
| **S1-semgrep-security-audit** | 89 | 57 | 4 | 18 | 21 | 93.44% | 76.00% | 83.82% | 14.71s |
| **S2-semgrep-java-plus-audit** | 89 | 57 | 4 | 18 | 21 | 93.44% | 76.00% | 83.82% | 14.76s |
| **S3-semgrep-java-error-only** | 23 | 15 | 4 | 60 | 21 | 78.95% | 20.00% | 31.91% | 11.16s |

---

### Diễn giải kết quả:

- **S0 (`p/java`):** Bộ quy tắc Java mặc định của Semgrep, đóng vai trò là **Non-LLM Baseline chính**.
- **S1 (`p/security-audit`):** Mở rộng bộ quy tắc sang chuyên sâu về kiểm thử an ninh (security audit), giúp tăng số lượng phát hiện đúng (TP tăng từ 43 lên 57) và đẩy Recall từ 57.33% lên 76.00% mà không tăng tin giả (FP vẫn giữ nguyên là 4).
- **S2 (`p/java` + `p/security-audit`):** Gộp cả hai bộ quy tắc để kiểm tra độ bao phủ tối đa. Kết quả trùng khớp với S1 do các quy tắc của `security-audit` đã bao hàm phần lớn các mẫu kiểm tra của `p/java`.
- **S3 (Chỉ lọc cảnh báo mức ERROR):** Giữ nguyên quy tắc `p/java` nhưng chỉ lọc các cảnh báo ở mức nghiêm trọng nhất (ERROR). Thử nghiệm này làm giảm đáng kể số lượng cảnh báo (từ 75 xuống 23), giúp chạy nhanh hơn một chút nhưng lại khiến tỷ lệ bỏ sót lỗ hổng tăng rất cao (Recall giảm xuống chỉ còn 20.00%).
