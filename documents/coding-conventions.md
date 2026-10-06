# Quy ước lập trình

**Quy ước này là luật của backend agent. Nếu có xung đột với ticket hoặc architecture documents, agent phải dừng lại và báo cho PM.**

* **Naming:** sử dụng `camelCase` cho biến và method, `PascalCase` cho class/interface/enum, `kebab-case` cho tên file khi phù hợp với convention của project.

* **Errors:** xử lý lỗi rõ ràng tại boundary; không được nuốt exception. API phải trả về **error response có cấu trúc**, không trả về string thuần.

* **Tests:** mọi thay đổi về behavior phải đi kèm test phù hợp. Phải report số lượng test và kết quả. Không báo `done` khi test/build đang fail.

* **Comments:** comment để giải thích **tại sao (why)**, không giải thích những thứ đã rõ từ code (**what**). Không đưa lịch sử ticket vào source code.

* **Contracts:** API response, HTTP status, authentication/authorization và **permission** là các contract của hệ thống. Thay đổi những contract này phải là quyết định được PM phê duyệt, không được tự ý chỉnh sửa trong quá trình implement.

* **Security:** password không bao giờ được lưu hoặc trả về dưới dạng plaintext. Sensitive information không được ghi vào log. Authentication và authorization phải được kiểm tra bằng test phù hợp.

* **Database:** thay đổi schema phải thông qua **Flyway migration**. Không sử dụng `ddl-auto: create` hoặc `update` để thay đổi schema trong môi trường phát triển chung.

* **Architecture:** tuân thủ architecture đã được định nghĩa trong `documents/`. Không tự ý thêm framework, infrastructure hoặc architectural pattern mới nếu ticket không yêu cầu.

* **Scope:** chỉ implement những gì được mô tả trong ticket. Nếu phát hiện vấn đề ngoài scope, ghi nhận trong `Notes` và báo cho PM thay vì tự ý mở rộng phạm vi.
