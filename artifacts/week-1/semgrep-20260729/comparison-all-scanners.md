# Bảng so sánh tổng hợp giữa các công cụ quét SAST (100 file OWASP BenchmarkJava đầu tiên)

Tất cả các công cụ bên dưới đều được chấm điểm độc lập dựa trên cùng tập dữ liệu Ground Truth của OWASP BenchmarkJava v1.2.  
Hai công cụ quét dùng LLM (OpenCodeReview và DeepSec) đều chạy qua 9Router với mô hình **`gc/gemini-2.5-flash`**. Semgrep là công cụ SAST truyền thống (Non-LLM), do đó không tiêu tốn Token.

**Phân định vai trò:**
- **Candidate (Công cụ cần đánh giá chính):** Vercel DeepSec / Pi backend.
- **LLM Comparator (Đối chiếu LLM):** Alibaba OpenCodeReview.
- **Non-LLM Baseline (Đối chiếu truyền thống):** Semgrep S0 (`p/java`).
- *(Script `dual_scan.py` chỉ đóng vai trò bộ điều phối thử nghiệm harness, không phải công cụ quét hay baseline).*

### Bảng so sánh hiệu năng tổng hợp

| Công cụ / Biến thể | Số cảnh báo | Tổng Tokens | Thời gian | TP | FP | FN | TN | Precision | Recall | F1-Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Alibaba OpenCodeReview** *(LLM Comparator)* | 131 | 1,216,883 | 2,408.00s (~40m) | 60 | 6 | 15 | 19 | **90.91%** | 80.00% | 85.11% |
| **Vercel DeepSec/Pi** *(Candidate, D0)* | 152 | 1,000,842 | 1,909.34s (~31m) | 64 | 10 | 11 | 15 | 86.49% | **85.33%** | **85.91%** |
| **Semgrep S0** (`p/java` - Non-LLM Baseline) | 75 | N/A | **17.04s** | 43 | 4 | 32 | 21 | 91.49% | 57.33% | 70.49% |
| **Semgrep S1** (`p/security-audit`) | 89 | N/A | 18.01s | 57 | 4 | 18 | 21 | **93.44%** | 76.00% | 83.82% |
| **Semgrep S2** (`p/java` + `p/security-audit`) | 89 | N/A | 17.93s | 57 | 4 | 18 | 21 | **93.44%** | 76.00% | 83.82% |
| **Semgrep S3** (`p/java`, chỉ lọc mức ERROR) | 23 | N/A | 12.13s | 15 | 4 | 60 | 21 | 78.95% | 20.00% | 31.91% |

---

### Tóm tắt các điểm đáng chú ý:

1. **So sánh LLM vs Non-LLM:**
   - **Tốc độ:** Semgrep vượt trội hoàn toàn về mặt thời gian (chỉ mất ~17-18 giây cho 100 file, trong khi các công cụ LLM mất từ 31 đến 40 phút).
   - **Độ chính xác (Precision):** Cả OpenCodeReview và Semgrep S1 đều đạt Precision rất cao (>90%), ít phát sinh cảnh báo giả (FP chỉ 4-6).
   - **Khả năng bao phủ (Recall):** Các scanner LLM (DeepSec 85.33%, OpenCodeReview 80.00%) có khả năng bắt lỗ hổng tốt hơn Semgrep S0 (57.33%). Tuy nhiên, khi chuyển sang bộ quy tắc `security-audit` (S1), Semgrep đã đẩy Recall lên **76.00%** và F1-Score đạt **83.82%**, tiệm cận hiệu năng của các mô hình LLM nhưng với chi phí thời gian gần như bằng 0.

2. **Vai trò của các biến thể Semgrep:**
   - **S0:** Baseline chuẩn non-LLM.
   - **S1 & S2:** Biến thể cấu hình ruleset mở rộng để so sánh độ nhạy lỗ hổng.
   - **S3:** Thử nghiệm giới hạn ngưỡng nghiêm trọng (severity-threshold ablation) nhằm giảm khối lượng báo cáo nhưng chấp nhận đánh đổi bằng việc bỏ sót nhiều lỗi.
