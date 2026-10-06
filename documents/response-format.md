# Định dạng phản hồi — cách agent báo cáo kết quả

Tin nhắn cuối của sub-agent là **dữ liệu dành cho PM, không phải văn bản mô tả cho con người**.

Luôn trả về **đúng cấu trúc** sau:

```text
Ticket: <backlog/NNNN-slug.md>

Status: done | blocked | needs-decision

Changed: <path:line>, <path:line>

Verified: <tests: N passed / build: green (tool) / request: <method path → status>>

Evidence: <bằng chứng cụ thể — tóm tắt kết quả test, dòng log khi ứng dụng khởi động, response body>

Notes: <các lưu ý, vấn đề cần xử lý tiếp, hoặc quyết định PM cần đưa ra>

Harness delta: <điều này giúp cải thiện hệ thống như thế nào, hoặc "None">
```

Nếu bị **blocked** hoặc cần **quyết định từ PM**, phải nêu rõ ngay ở đầu phản hồi và **dừng lại**.

Không được tự suy đoán hoặc tự quyết định khi gặp vấn đề liên quan đến **contract hoặc product decision**.
