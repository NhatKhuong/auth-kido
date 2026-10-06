# api — backend service

Backend service của dự án **Authentication & User Management**.

* **Stack:** Java 21 · Spring Boot · Spring Security · JPA/Hibernate · PostgreSQL · Flyway

* **Phụ trách:** api sub-agent (`../../management/.claude/agents/api.md`)

* **Luật của backend:** [`documents/`](documents/) — architecture, coding conventions, database design, API contracts và format mà agent sử dụng để report kết quả.

* **Authentication:** JWT + Spring Security.

* **Authorization:** RBAC với Role và Permission, cho phép mở rộng thêm role/permission mà không phải thay đổi business logic hiện tại.

* **Các chức năng chính:**

    * Đăng nhập
    * Xem thông tin tài khoản
    * Đổi mật khẩu
    * Phân quyền User / Admin
    * Quản lý user theo permission

PM **không chỉnh sửa trực tiếp** thư mục này. PM giao việc cho `api` agent thông qua ticket; **ticket là spec** mà agent phải tuân theo.
