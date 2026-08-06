# BenchmarkJava first-100 methodology

- Upstream: OWASP BenchmarkJava, commit `79b9bd6177e07991a9c11dc19e457c840e229931`.
- Scope: 100 tên file zero-padded đầu tiên, từ `BenchmarkTest00001.java` đến `BenchmarkTest00100.java`.
- Label distribution: 75 positive, 25 negative.
- Leakage control: scanner chỉ nhận Java source. Ground truth CSV và metadata không được mount/gửi vào scanner.
- Scoring: sau khi scan kết thúc, finding được map về CWE/category mong đợi rồi tính TP/FP/FN/TN, precision, recall và F1.
- Coverage rule: chỉ công bố metrics khi đủ 100/100 case. Scanner lỗi không được diễn giải thành “0 finding”.

Đây là sample theo thứ tự file để tái hiện đúng Week 1, không phải sample cân bằng đại diện cho toàn bộ 2.740 case. Vì vậy kết quả chỉ dùng so sánh các scanner trên cùng scope này.
