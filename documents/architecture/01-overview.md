# Kiến trúc — Tổng quan

Đây là backend service cho bài toán **Authentication & User Management**, tập trung vào authentication, authorization và quản lý tài khoản người dùng.

## 1. Công nghệ

* **Ngôn ngữ:** Java 21
* **Framework:** Spring Boot
* **Security:** Spring Security + JWT
* **ORM:** Spring Data JPA / Hibernate
* **Database:** PostgreSQL
* **Database Migration:** Flyway
* **Validation:** Jakarta Bean Validation
* **Testing:** JUnit 5 + Mockito + Spring Boot Test
* **Build:** Maven

---

## 2. Kiến trúc

Backend sử dụng **Layered Architecture** với các layer có trách nhiệm rõ ràng.

```text
HTTP Request
     │
     ↓
JWT Authentication Filter
     │
     ↓
Spring Security
(Authentication / Authorization)
     │
     ↓
Controller
     │
     ↓
Service
     │
     ↓
Repository
     │
     ↓
PostgreSQL
```

### 2.1 Package Structure

```text
com.example.auth
│
├── controller
├── dto
│   ├── request
│   └── response
├── service
│   ├── UserService.java
│   ├── UserServiceImpl.java
│   ├── AuthenticationService.java
│   └── AuthenticationServiceImpl.java
├── repository
├── entity
├── security
├── mapper
├── exception
└── config
```

### 2.2 Controller Layer

Chịu trách nhiệm giao tiếp với client thông qua HTTP.

Trách nhiệm:

* Nhận HTTP request.
* Validate input.
* Gọi Service.
* Trả về HTTP response.
* Không chứa business logic.

### 2.3 Service Layer

Chứa business logic và điều phối các use case của hệ thống.

Trách nhiệm:

* Authentication flow.
* Refresh Token flow.
* Lấy thông tin tài khoản.
* Đổi password.
* User management.
* Các business rule liên quan đến user và authorization.
* Quản lý transaction boundary khi cần.

Service được định nghĩa thông qua interface khi phù hợp. Controller phụ thuộc vào Service interface thay vì implementation cụ thể.

### 2.4 Repository Layer

Chịu trách nhiệm truy cập database thông qua Spring Data JPA.

Repository chỉ tập trung vào persistence và query dữ liệu.

Business logic không được đặt trong Repository.

### 2.5 Entity Layer

Entity đại diện cho các dữ liệu được persistence trong database.

Các entity chính:

```text
User
Role
Permission
RefreshToken
```

Entity tập trung vào data model và persistence mapping.

### 2.6 Security Layer

Spring Security chịu trách nhiệm:

* Xác thực JWT Access Token.
* Tạo `Authentication`.
* Đưa authentication information vào `SecurityContext`.
* Kiểm tra authentication.
* Kiểm tra authorization và Permission.
* Bảo vệ các endpoint yêu cầu authentication.

JWT implementation và security configuration được đặt trong Security Layer.

### 2.7 Dependency Rule

Các layer phụ thuộc theo hướng:

```text
Controller
    ↓
Service
    ↓
Repository
    ↓
Database
```

Security là cross-cutting layer, tích hợp với request processing và authorization.

Các layer không truy cập trực tiếp implementation của layer bên dưới khi không cần thiết.

Interface được sử dụng tại những boundary có ý nghĩa, đặc biệt đối với Service Layer.

Không yêu cầu tạo interface cho mọi class vì mục tiêu của project là **đơn giản, rõ ràng và tránh over-engineering**.

### 2.8 Design Principles

Project ưu tiên:

* Separation of concerns.
* Loose coupling.
* Dependency inversion ở những boundary phù hợp.
* Business logic nằm ở Service Layer.
* Persistence logic nằm ở Repository Layer.
* HTTP logic nằm ở Controller Layer.
* Security logic nằm ở Security Layer.
* Không đưa framework abstraction vào những nơi không cần thiết.

Kiến trúc được giữ ở mức đơn giản phù hợp với phạm vi **Authentication & User Management**, không sử dụng DDD, CQRS, Event Sourcing hoặc Microservices.


---

## 3. Authentication

Hệ thống sử dụng **JWT Access Token + Refresh Token**.

### Access Token

Access Token là JWT token có thời gian sống ngắn.

Ví dụ:

```text
Expiration: 15 minutes
```

Access Token được gửi trong mỗi request cần authentication:

```http
Authorization: Bearer <accessToken>
```

Access Token chứa các thông tin cần thiết để xác định user và authorities.

JWT phải:

* Được verify chữ ký.
* Kiểm tra expiration.
* Không chứa sensitive information.
* Không được sử dụng như Refresh Token.

### Refresh Token

Refresh Token có thời gian sống dài hơn Access Token.

Ví dụ:

```text
Expiration: 7 days
```

Refresh Token **chỉ được sử dụng để cấp Access Token mới** và không được sử dụng trực tiếp để truy cập business API.

Refresh Token được lưu dưới dạng **hash** trong database thay vì lưu plaintext.

Ví dụ:

```text
refresh_tokens
-------------------------
id
user_id
token_hash
expires_at
created_at
```

Khi Refresh Token được sử dụng:

```text
Client
  │
  │ Refresh Token
  ↓
POST /api/auth/refresh
  │
  ↓
Hash token
  │
  ↓
Tìm token trong database
  │
  ├── Không tồn tại → reject
  ├── Expired → reject
  └── Hợp lệ
        │
        ↓
Generate Access Token mới
```

### Login flow

```text
POST /api/auth/login
        │
        ↓
 username + password
        │
        ↓
 AuthenticationService
        │
        ├── tìm User
        ├── kiểm tra password bằng PasswordEncoder
        ├── tạo Access Token
        └── tạo Refresh Token
        │
        ↓
Access Token + Refresh Token
```

Response:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

Trong đó:

```text
Access Token
→ sống ngắn
→ dùng để gọi API

Refresh Token
→ sống dài hơn
→ chỉ dùng để lấy Access Token mới
```

---

## 4. Authorization — RBAC

Hệ thống sử dụng **RBAC (Role-Based Access Control)** với Role và Permission.

```text
User
 │
 │ N
 ↓
UserRole
 │
 │ N
 ↓
Role
 │
 │ N
 ↓
RolePermission
 │
 │ N
 ↓
Permission
```

Database gồm:

```text
users
roles
permissions
user_roles
role_permissions
refresh_tokens
```

Ví dụ:

```text
ROLE_USER
 ├── ACCOUNT_READ
 └── PASSWORD_CHANGE

ROLE_ADMIN
 ├── ACCOUNT_READ
 ├── PASSWORD_CHANGE
 ├── USER_READ
 └── USER_MANAGE
```

Authorization ưu tiên kiểm tra **Permission** thay vì hard-code business logic theo Role:

```java
@PreAuthorize("hasAuthority('USER_READ')")
```

Điều này cho phép sau này thêm:

```text
MANAGER
AUDITOR
SUPPORT
```

mà không cần thay đổi business logic của các API hiện tại.

Ở phạm vi bài test, chỉ cần seed `USER` và `ADMIN`.

---

## 5. Các chức năng chính

### Authentication

```text
POST /api/auth/login
POST /api/auth/refresh
```

### Account

```text
GET /api/users/me
PUT /api/users/me/password
```

### User management

```text
GET /api/admin/users
```

Các endpoint được bảo vệ bởi Spring Security và RBAC.

---

## 6. Database

Sử dụng PostgreSQL.

Schema được quản lý bằng **Flyway migration**.

Ví dụ:

```text
V1__create_users.sql
V2__create_roles_and_permissions.sql
V3__create_user_role_mapping.sql
V4__create_role_permission_mapping.sql
V5__create_refresh_tokens.sql
V6__seed_default_roles_and_permissions.sql
```

Migration là **versioned và forward-only**.

Không sử dụng:

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: create
```

hoặc `update` để quản lý schema.

Ứng dụng sử dụng:

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: validate
```

để Hibernate kiểm tra entity mapping với schema hiện tại.

### Refresh Token schema

```text
refresh_tokens
--------------------------------
id
user_id
token_hash
expires_at
created_at
```

`token_hash` được sử dụng để kiểm tra Refresh Token mà không cần lưu token plaintext.

---

## 7. API Contract

API sử dụng JSON.

### Login

```http
POST /api/auth/login
```

Response:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

### Refresh

```http
POST /api/auth/refresh
```

Request:

```json
{
  "refreshToken": "..."
}
```

Response:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

Account API không bao giờ trả về:

```text
password
passwordHash
refreshToken
tokenHash
```

Error response sử dụng một format thống nhất, ví dụ:

```json
{
  "code": "INVALID_CREDENTIALS",
  "message": "Username or password is incorrect"
}
```

HTTP status phải phản ánh đúng loại lỗi:

```text
400 → Invalid request
401 → Unauthenticated / invalid token
403 → Authenticated nhưng không có quyền
404 → Resource not found
409 → Conflict
```

API contract là contract của hệ thống và không được tự ý thay đổi nếu không có quyết định từ PM.

---

## 8. Configuration

Configuration được truyền thông qua environment variables.

Ví dụ:

```text
DATABASE_URL
DATABASE_USERNAME
DATABASE_PASSWORD

JWT_SECRET
JWT_ACCESS_TOKEN_EXPIRATION
JWT_REFRESH_TOKEN_EXPIRATION
```

Cung cấp:

```text
.env.example
```

để mô tả các biến cần thiết.

**Không commit secret thật vào repository.**

---

## 9. Testing

Các behavior quan trọng phải được kiểm thử.

### Authentication

* Login thành công.
* Sai username/password.
* Access Token được tạo đúng.
* JWT signature được verify.
* JWT hết hạn hoặc không hợp lệ.
* Request không có Access Token → `401`.

### Refresh Token

* Refresh Token hợp lệ → tạo Access Token mới.
* Refresh Token không tồn tại → reject.
* Refresh Token hết hạn → reject.
* Refresh Token không thể được sử dụng để truy cập business API trực tiếp.

### Authorization

* USER truy cập endpoint được phép → `200`.
* USER truy cập endpoint yêu cầu permission của ADMIN → `403`.
* ADMIN truy cập endpoint quản trị → `200`.

### Password

* Đổi password thành công.
* Current password không đúng → reject.
* Password mới được hash trước khi lưu.
* Password không xuất hiện trong response hoặc log.

### API

* Validation input.
* Error response.
* Không expose password/password hash/token hash.

Test phải được chạy trước khi agent báo `done`.

---



## 10. Nguyên tắc thiết kế

Dự án ưu tiên:

1. **Security correctness**
2. **Đúng business requirement**
3. **API và database rõ ràng**
4. **Có test và verification**
5. **Maintainability**
6. **Khả năng mở rộng hợp lý**
7. **Không over-engineering**

Mục tiêu không phải xây dựng một hệ thống production hoàn chỉnh, mà là thể hiện khả năng thiết kế và implement một backend service **đơn giản, an toàn, có cấu trúc và có khả năng mở rộng**.

**Last updated: 2026-10-06**
