# api — Authentication & User Management

Backend service: đăng nhập, xem thông tin tài khoản, đổi mật khẩu, phân quyền Admin/User.
Kèm một UI tĩnh tối thiểu để thao tác đủ 4 chức năng trên bằng trình duyệt.

* **Stack:** Java 21 · Spring Boot 4.1 · Spring Security (JWT access + refresh) · Spring Data
  JPA/Hibernate · PostgreSQL · Flyway · Maven · JUnit 5 + Mockito + Spring Boot Test + Testcontainers
* **Lý do chọn stack, chọn JWT thay vì session cookie, chọn RBAC theo permission thay vì theo
  role:** [ADR 0001](../../management/decisions/0001-auth-backend-stack.md).
  Refresh token rotate mỗi lần dùng:
  [ADR 0003](../../management/decisions/0003-refresh-token-rotation.md).
* **Thiết kế chi tiết** (kiến trúc, API contract, schema, nguyên tắc test):
  [`documents/architecture/01-overview.md`](documents/architecture/01-overview.md).

---

## 1. Yêu cầu môi trường

| Cần | Ghi chú |
| --- | --- |
| **JDK 21 trở lên** | Project compile ở release 21. Maven wrapper (`mvnw`) dùng `JAVA_HOME`, nên `JAVA_HOME` phải trỏ tới JDK 21+. |
| **Docker** (đang chạy) | Dùng cho PostgreSQL trong `docker-compose.yml`, **và** cho test — test tích hợp dùng Testcontainers, không có Docker thì `./mvnw test` fail. |
| Port `5432` và `8080` còn trống | Postgres và app. |

Không cần cài Maven (đã có wrapper trong repo) và không cần Node/npm (UI là HTML + vanilla JS
thuần, không có build frontend).

---

## 2. Chạy local

Chạy trong thư mục `projects/api`.

```bash
# 1. Cấu hình: copy file mẫu. ".env" được git-ignore.
cp .env.example .env

# 2. Database
docker compose up -d --wait

# 3. App (Flyway tự chạy migration + seed khi khởi động)
./mvnw spring-boot:run
```

> **Windows (PowerShell / cmd):** thay `./mvnw` bằng `.\mvnw.cmd` ở mọi lệnh trong README, và `cp`
> bằng `copy`. Các ví dụ `curl` bên dưới viết theo cú pháp bash (Git Bash, macOS, Linux) — trên
> PowerShell quy tắc nháy khác nên dễ nhất là dùng Git Bash, hoặc dùng UI ở §4.

Khởi động xong, log sẽ in ra:

```text
o.f.core.internal.command.DbMigrate : Successfully applied 7 migrations to schema "public", now at version v7
o.s.boot.tomcat.TomcatWebServer     : Tomcat started on port 8080 (http) with context path '/'
com.example.auth.AuthApplication    : Started AuthApplication in 7.065 seconds
```

Mở **<http://localhost:8080/>** → tự chuyển sang trang đăng nhập.

`.env` copy từ `.env.example` là chạy được ngay (các giá trị trong đó là placeholder cho môi trường
phát triển). Trước khi dùng cho bất cứ việc gì ngoài thử local, thay `JWT_SECRET` bằng một giá trị
ngẫu nhiên dài — app **từ chối khởi động** nếu secret ngắn hơn 32 byte:

```text
Caused by: java.lang.IllegalStateException: JWT_SECRET is too short: 9 bytes, but HS256 needs
at least 32. Set JWT_SECRET in projects/api/.env to a longer random value
(for example: openssl rand -base64 48).
```

```bash
openssl rand -base64 48   # trên Windows: có sẵn trong Git Bash, không có trong PowerShell
```

Dừng: `Ctrl+C` để tắt app, `docker compose down` để tắt database (thêm `-v` nếu muốn xoá luôn dữ
liệu và chạy lại migration từ đầu).

---

## 3. Tài khoản seed

Do `db/migration/V7__seed_demo_users.sql` tạo; trong database chỉ có **BCrypt hash**, không có
plaintext. Không có endpoint đăng ký — đây là 2 tài khoản để thử.

| Username | Password | Role | Permissions |
| --- | --- | --- | --- |
| `admin` | `admin12345` | `ROLE_ADMIN` | `ACCOUNT_READ`, `PASSWORD_CHANGE`, `USER_READ`, `USER_MANAGE` |
| `user` | `user12345` | `ROLE_USER` | `ACCOUNT_READ`, `PASSWORD_CHANGE` |

Nếu đã đổi mật khẩu khi thử và muốn về trạng thái ban đầu: tắt app, rồi
`docker compose down -v && docker compose up -d --wait`, rồi khởi động lại app.

---

## 4. UI (trình duyệt)

| URL | Nội dung |
| --- | --- |
| <http://localhost:8080/> | Trang vào, chuyển tiếp sang `login.html` |
| `/login.html` | Form đăng nhập → `POST /api/auth/login` |
| `/account.html` | Thông tin tài khoản → `GET /api/users/me`; nút đăng xuất; link sang 2 trang dưới |
| `/password.html` | **Trang riêng** để đổi mật khẩu → `PUT /api/users/me/password` |
| `/admin.html` | Danh sách người dùng → `GET /api/admin/users` |

Thử đủ 4 yêu cầu của đề:

1. Mở <http://localhost:8080/>, đăng nhập `user` / `user12345`.
2. Trang **Thông tin tài khoản** hiện id, username, role và permission.
3. Bấm **Đổi mật khẩu** → sang `/password.html` → nhập mật khẩu hiện tại + mật khẩu mới (≥ 8 ký tự).
4. Phân quyền: với `user`, link **Danh sách người dùng (admin)** không hiện, và vào thẳng
   `/admin.html` thì trang báo `403 FORBIDDEN`. Đăng xuất, đăng nhập lại bằng `admin` /
   `admin12345` → link hiện và bảng người dùng hiển thị.

Ẩn/hiện link là theo **permission** đọc từ `GET /api/users/me`, và chỉ để tiện hiển thị — quyết
định cuối cùng vẫn ở server: endpoint vẫn trả `403` cho caller không có quyền.

Access token được giữ ở `sessionStorage`; UI không lưu refresh token, gặp `401` thì xoá token và
quay về trang đăng nhập (nên để trống ~15 phút là phải đăng nhập lại).

---

## 5. Endpoint

| Method | Path | Auth | Permission | Thành công | Lỗi |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/api/auth/login` | không | — | `200` tokens | `400 VALIDATION_ERROR`, `401 INVALID_CREDENTIALS` |
| `POST` | `/api/auth/refresh` | không | — | `200` tokens mới | `400 VALIDATION_ERROR`, `401 INVALID_REFRESH_TOKEN` |
| `GET` | `/api/users/me` | Bearer | `ACCOUNT_READ` | `200` account | `401 UNAUTHORIZED`, `403 FORBIDDEN` |
| `PUT` | `/api/users/me/password` | Bearer | `PASSWORD_CHANGE` | `204` không body | `400 VALIDATION_ERROR`, `400 INVALID_CURRENT_PASSWORD`, `401`, `403` |
| `GET` | `/api/admin/users` | Bearer | `USER_READ` | `200` danh sách | `401 UNAUTHORIZED`, `403 FORBIDDEN` |

Mọi lỗi dùng cùng một shape:

```json
{"code":"UNAUTHORIZED","message":"Access token is missing, invalid or expired"}
```

Permission được khai báo bằng `@PreAuthorize("hasAuthority('USER_READ')")` ngay cạnh handler,
**không** bằng URL rule và **không** theo tên role — thêm role mới chỉ là thêm dữ liệu, không sửa
code (ADR 0001 §Decision 3). `/api/**` là default-deny, nên endpoint thêm sau được bảo vệ ngay.

---

## 6. Thử bằng `curl`

Các ví dụ dưới đây chạy trực tiếp được (bash). Access/refresh token mỗi lần chạy sẽ khác nhau, và
trong README token được **cắt ngắn** cho dễ đọc — giá trị thật dài hơn nhiều.

### 6.1 Đăng nhập

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin12345"}'
```

```json
{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJz…","refreshToken":"ylbbQ8-PlL-_TAED1PAAsOrtp…","tokenType":"Bearer","expiresIn":900}
```

Sai mật khẩu → `401`; thiếu field → `400`:

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"nope"}'
# {"code":"INVALID_CREDENTIALS","message":"Username or password is incorrect"}

curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin"}'
# {"code":"VALIDATION_ERROR","message":"password: password is required"}
```

Copy `accessToken` vào một biến shell để dùng cho các bước sau:

```bash
ACCESS_TOKEN='<dán accessToken ở trên vào đây>'
```

### 6.2 Thông tin tài khoản

```bash
curl -s http://localhost:8080/api/users/me -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{"id":1,"username":"admin","roles":["ROLE_ADMIN"],"permissions":["ACCOUNT_READ","PASSWORD_CHANGE","USER_MANAGE","USER_READ"]}
```

Không có token → `401` (không phải `403`):

```bash
curl -s http://localhost:8080/api/users/me
# {"code":"UNAUTHORIZED","message":"Access token is missing, invalid or expired"}
```

### 6.3 Đổi mật khẩu

Thành công là `204 No Content`, body rỗng — không có chỗ nào để lỡ echo lại mật khẩu.

```bash
curl -s -i -X PUT http://localhost:8080/api/users/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"currentPassword":"admin12345","newPassword":"newpass12345"}' | head -1
# HTTP/1.1 204
```

Mật khẩu hiện tại sai, hoặc mật khẩu mới ngắn hơn 8 ký tự → `400` với 2 code khác nhau:

```bash
curl -s -X PUT http://localhost:8080/api/users/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"currentPassword":"wrong-one","newPassword":"newpass12345"}'
# {"code":"INVALID_CURRENT_PASSWORD","message":"Current password is incorrect"}

curl -s -X PUT http://localhost:8080/api/users/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"currentPassword":"admin12345","newPassword":"short"}'
# {"code":"VALIDATION_ERROR","message":"newPassword: newPassword must be between 8 and 72 characters"}
```

Sau ví dụ trên, mật khẩu của `admin` **đã là** `newpass12345`. Đổi mật khẩu không thu hồi token
đang sống (xem §9), nên `$ACCESS_TOKEN` vẫn dùng được để đổi ngược lại về mật khẩu seed:

```bash
curl -s -i -X PUT http://localhost:8080/api/users/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"currentPassword":"newpass12345","newPassword":"admin12345"}' | head -1
# HTTP/1.1 204
```

### 6.4 Phân quyền: `ADMIN` xem được, `USER` bị chặn

```bash
curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
[{"id":1,"username":"admin","roles":["ROLE_ADMIN"]},{"id":2,"username":"user","roles":["ROLE_USER"]}]
```

Cùng endpoint, chỉ đổi tài khoản — đăng nhập bằng `user` rồi gọi lại:

```bash
USER_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"user","password":"user12345"}' \
  | sed -E 's/.*"accessToken":"([^"]*)".*/\1/')

curl -s http://localhost:8080/api/users/me    -H "Authorization: Bearer $USER_TOKEN"
# {"id":2,"username":"user","roles":["ROLE_USER"],"permissions":["ACCOUNT_READ","PASSWORD_CHANGE"]}

curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $USER_TOKEN"
# {"code":"FORBIDDEN","message":"You do not have permission to perform this action"}

curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer not-a-token"
# {"code":"UNAUTHORIZED","message":"Access token is missing, invalid or expired"}
```

`403` ở trên là do thiếu `USER_READ`, không phải do token lỗi: token hỏng cho `401`, và cùng token
`user` đó gọi `/api/users/me` vẫn `200`.

### 6.5 Refresh token

Refresh **rotate mỗi lần dùng**: response trả về cả access token mới **và** refresh token mới, và
token vừa gửi lên lập tức hết hiệu lực
([ADR 0003](../../management/decisions/0003-refresh-token-rotation.md)). Client bắt buộc phải lưu
lại refresh token mới.

```bash
LOGIN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"user","password":"user12345"}')
REFRESH_TOKEN=$(echo "$LOGIN" | sed -E 's/.*"refreshToken":"([^"]*)".*/\1/')

curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}"
```

```json
{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJz…","refreshToken":"TNBSy83VraCsAscI3X1fmEf…","tokenType":"Bearer","expiresIn":900}
```

Dùng lại chính refresh token cũ → `401`:

```bash
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}"
# {"code":"INVALID_REFRESH_TOKEN","message":"Refresh token is invalid or expired"}
```

Refresh token không dùng được như access token:

```bash
curl -s http://localhost:8080/api/users/me -H "Authorization: Bearer $REFRESH_TOKEN"
# {"code":"UNAUTHORIZED","message":"Access token is missing, invalid or expired"}
```

Trong database, bảng `refresh_tokens` chỉ lưu SHA-256 **hash** của token, không lưu plaintext.

---

## 7. Test

Cần Docker đang chạy: Testcontainers tự dựng một PostgreSQL riêng cho test, không dùng database
của `docker-compose.yml`.

```bash
./mvnw test          # unit + integration test
./mvnw clean verify  # build sạch + test + đóng gói jar
```

Kết quả hiện tại:

```text
Tests run: 156, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Phủ các nhóm behavior: login thành công/thất bại, ký và verify JWT, token hết hạn hoặc không hợp
lệ, refresh + rotation + reject token đã dùng, đổi mật khẩu (hash trước khi lưu, sai mật khẩu hiện
tại bị từ chối), RBAC `200/401/403`, validation, error response, không expose
password/password hash/token hash, và UI tĩnh (file tĩnh đọc được khi chưa đăng nhập nhưng
`/api/**` vẫn `401`).

---

## 8. Chạy từ jar

```bash
./mvnw clean package
java -jar target/auth-0.0.1-SNAPSHOT.jar
```

**Hai lỗi rất dễ gặp ở bước này:**

1. **`java` trên `PATH` có thể không phải JDK 21.** Nếu nó là bản cũ hơn thì jar không chạy được,
   kể cả khi `./mvnw package` vừa thành công (vì Maven dùng `JAVA_HOME`, không dùng `PATH`):

   ```text
   java.lang.UnsupportedClassVersionError: org/springframework/boot/loader/launch/JarLauncher
   has been compiled by a more recent version of the Java Runtime (class file version 61.0),
   this version of the Java Runtime only recognizes class file versions up to 52.0
   ```

   Gọi JDK 21+ tường minh thay vì tin `PATH`:

   ```bash
   "$JAVA_HOME/bin/java" -jar target/auth-0.0.1-SNAPSHOT.jar
   ```

2. **`./mvnw clean` fail nếu app đang chạy từ jar** — trên Windows, JVM giữ khoá trên chính file
   jar:

   ```text
   [ERROR] Failed to execute goal org.apache.maven.plugins:maven-clean-plugin:3.5.0:clean
   (default-clean) on project auth: Failed to clean project: Failed to delete
   ...\projects\api\target\auth-0.0.1-SNAPSHOT.jar: The process cannot access the file because
   it is being used by another process
   ```

   Tắt app trước khi build lại. (Nếu app chạy bằng `./mvnw spring-boot:run` thì `clean` lại
   thành công — nó nạp class từ `target/classes` chứ không giữ khoá trên jar. Nghĩa là `clean`
   **không** phải cách đáng tin để biết app đã tắt hay chưa; dùng `jps -l` ở dưới.)

Thêm một cái bẫy khi debug: trước khi tin một lượt `curl`, kiểm tra **tiến trình nào đang giữ port
8080** — rất dễ đang nói chuyện với một app cũ do IDE chạy từ `target/classes`:

```bash
jps -l | grep -i auth
# 21604 target/auth-0.0.1-SNAPSHOT.jar          <- chạy từ jar vừa build
# 12036 com.example.auth.AuthApplication        <- chạy từ target/classes (IDE / spring-boot:run)
```

---

## 9. Giới hạn đã biết (cố ý, trong phạm vi bài test)

* **Đổi mật khẩu không thu hồi refresh token** đã phát hành — token cũ còn dùng được tới khi hết
  hạn. Đang chờ Owner quyết:
  [backlog 0010](../../management/backlog/0010-api-revoke-refresh-on-password-change.md).
* **`405` / `415` bị trả thành `500 INTERNAL_ERROR`** (ví dụ `POST /api/admin/users` khi endpoint
  chỉ có `GET`): catch-all exception handler khớp trước handler mặc định của Spring MVC. Đã ghi
  nhận ở [bug 0001](../../management/bugs/0001-api-catch-all-handler-masks-405-415-406.md).
* **UI không tự refresh token:** để trống ~15 phút là phải đăng nhập lại.
* **`refresh_tokens` không có cleanup:** mỗi lần login sinh thêm một row; rotation chỉ thay thế row
  khi refresh.
* **Không có revoke cho access token** (JWT stateless) — chấp nhận được vì TTL 15 phút.
* **Không có endpoint tạo/sửa/xoá user:** permission `USER_MANAGE` đã được seed nhưng chưa có
  endpoint nào dùng; `GET /api/admin/users` là read-only.
* Không deploy, không CI, không Dockerfile cho app — đề không yêu cầu.

---

## 10. Quy ước làm việc trong repo này

[`documents/`](documents/) là source of truth của surface này — architecture, coding conventions,
API contract và format mà agent dùng để report. Phụ trách: `api` sub-agent
([`../../management/.claude/agents/api.md`](../../management/.claude/agents/api.md)).
PM **không chỉnh sửa trực tiếp** thư mục này: PM giao việc qua ticket trong `management/backlog/`,
và **ticket là spec** mà agent phải tuân theo.
