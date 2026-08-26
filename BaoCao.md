# BÁO CÁO BÀI 4: LẬP TRÌNH LỚP PHÒNG VỆ — BẢO MẬT SQL & CHỐNG TRÀN TOKEN CHO `execute_sql_query` TOOL

**Dự án:** RikkeiExpress AI Integration  
**Chủ đề:** AI Data Analyst Agent — Defensive SQL Query Sanitization  
**Tác giả:** Đội ngũ Kỹ sư An toàn Thông tin & AI Rikkei  

---

## 1. Phân Tích Bối Cảnh & Nguy Cơ An Toàn Thông Tin

Khi tích hợp công cụ `execute_sql_query` vào MCP Server cho phép AI Agent tự sinh và thực thi câu lệnh SQL, hệ thống đối mặt với 2 nguy cơ chí mạng:

```
                            CÁC NGUY CƠ KHI KHÔNG CÓ LỚP PHÒNG VỆ
  ┌──────────────────────────────────────────────────┬──────────────────────────────────────────────────┐
  │ NGUY CƠ 1: PHÁ HOẠI DỮ LIỆU                      │ NGUY CƠ 2: TRÀN BỘ NHỚ & TOKEN (DoS)             │
  ├──────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ - Kẻ tấn công dùng Prompt Injection lừa LLM sinh │ - LLM sinh `SELECT * FROM deliveries` không      │
  │   các lệnh DDL/DML (DROP, DELETE, TRUNCATE,...). │   giới hạn, kéo về hàng triệu dòng dữ liệu.      │
  │ - Dẫn đến xóa sạch database hoặc sửa đổi dữ liệu │ - Làm sập RAM (OutOfMemoryError) JVM và làm tràn │
  │   phi pháp mà không thể phục hồi.                │   Context Window của LLM (gây nghẽn DoS).        │
  └──────────────────────────────────────────────────┴──────────────────────────────────────────────────┘
```

---

## 2. Thiết Kế Kiến Trúc 3 Quy Tắc Phòng Vệ Trong `SafeSqlValidator`

```
                                      [Raw SQL Input]
                                             │
                                             ▼
                 Quy tắc 1: Bắt đầu bằng SELECT? ──No──► [Ném SecurityException]
                                             │
                                            Yes
                                             ▼
                 Quy tắc 2: Chứa từ cấm / -- / ; ? ──Yes──► [Ném SecurityException]
                                             │
                                            No
                                             ▼
                 Quy tắc 3: Kiểm tra mệnh đề LIMIT:
                            - Chưa có LIMIT   ➔ Nối thêm ` LIMIT 100`
                            - Có LIMIT N > 100 ➔ Ép về `LIMIT 100`
                            - Có LIMIT N <= 100 ➔ Giữ nguyên
                                             │
                                             ▼
                                    [Sanitized SQL Output]
```

---

## 3. Mã Nguồn Lớp `SafeSqlValidator.java`

```java
package com.rikkei.mcp.security;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SafeSqlValidator {

    private static final Pattern SELECT_PREFIX_PATTERN = Pattern.compile("(?is)^SELECT\\b.*");
    private static final Pattern FORBIDDEN_KEYWORDS_PATTERN = Pattern.compile("(?i)\\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|GRANT|REVOKE|EXEC)\\b");
    private static final Pattern LIMIT_PATTERN = Pattern.compile("(?i)\\bLIMIT\\s+(\\d+)");

    public static String validateAndSanitize(String rawSql) {
        if (rawSql == null || rawSql.trim().isEmpty()) {
            throw new SecurityException("Câu lệnh SQL không được để trống.");
        }

        String trimmedSql = rawSql.trim();

        if (!SELECT_PREFIX_PATTERN.matcher(trimmedSql).matches()) {
            throw new SecurityException("Chỉ cho phép thực thi câu lệnh SELECT tra cứu dữ liệu.");
        }

        if (trimmedSql.contains("--") || trimmedSql.contains("/*") || trimmedSql.contains("*/")) {
            throw new SecurityException("Phát hiện ký tự comment SQL nguy hiểm bị cấm.");
        }

        if (trimmedSql.contains(";")) {
            throw new SecurityException("Phát hiện ký tự phân tách đa lệnh (;) bị cấm.");
        }

        Matcher keywordMatcher = FORBIDDEN_KEYWORDS_PATTERN.matcher(trimmedSql);
        if (keywordMatcher.find()) {
            throw new SecurityException("Phát hiện từ khóa SQL nguy hiểm bị cấm: " + keywordMatcher.group(1).toUpperCase());
        }

        Matcher limitMatcher = LIMIT_PATTERN.matcher(trimmedSql);
        if (limitMatcher.find()) {
            long limitValue = Long.parseLong(limitMatcher.group(1));
            if (limitValue > 100) {
                return limitMatcher.replaceFirst("LIMIT 100");
            }
            return trimmedSql;
        }

        return trimmedSql + " LIMIT 100";
    }
}
```

---

## 4. Bảng Kết Quả Thực Thi 5 Test Cases Bắt Buộc

| STT | Input SQL | Quy tắc áp dụng | Expected Output | Actual Output | Trạng thái |
| :---: | :--- | :---: | :--- | :--- | :---: |
| **1** | `SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED'` | Quy tắc 3 (Chưa có LIMIT) | Thêm ` LIMIT 100` vào cuối câu lệnh | `SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED' LIMIT 100` | **PASSED (100%)** |
| **2** | `select count(*) from deliveries limit 20` | Quy tắc 3 (LIMIT 20 $\le$ 100) | Giữ nguyên mệnh đề LIMIT | `select count(*) from deliveries limit 20` | **PASSED (100%)** |
| **3** | `SELECT * FROM deliveries LIMIT 5000` | Quy tắc 3 (LIMIT 5000 > 100) | Cưỡng chế ép về `LIMIT 100` | `SELECT * FROM deliveries LIMIT 100` | **PASSED (100%)** |
| **4** | `DROP TABLE deliveries;` | Quy tắc 1 (Không phải SELECT) & Quy tắc 2 (Từ khóa DROP, dấu `;`) | Ném ngoại lệ `SecurityException` | Throws `SecurityException("Chỉ cho phép thực thi câu lệnh SELECT tra cứu dữ liệu.")` | **PASSED (100%)** |
| **5** | `SELECT * FROM deliveries WHERE 1=1 -- delete from deliveries` | Quy tắc 2 (Chứa comment `--`, từ khóa DELETE) | Ném ngoại lệ `SecurityException` | Throws `SecurityException("Phát hiện ký tự comment SQL nguy hiểm bị cấm.")` | **PASSED (100%)** |

---

## 5. Minh Chứng Chạy Thực Tế (JUnit 5 Test Execution Logs)

```text
2026-08-26 13:40:02.140 [main] INFO  o.s.b.t.c.SpringBootTestContextBootstrapper - Starting test execution for SafeSqlValidatorTest
2026-08-26 13:40:02.350 [main] INFO  c.r.m.s.SafeSqlValidatorTest - Running testCase1_NoLimitAppended()...
2026-08-26 13:40:02.358 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Input: "SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED'"
2026-08-26 13:40:02.360 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Output: "SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED' LIMIT 100" [MATCH]
2026-08-26 13:40:02.365 [main] INFO  c.r.m.s.SafeSqlValidatorTest - Running testCase2_LimitUnderOrEqual100Preserved()...
2026-08-26 13:40:02.368 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Input: "select count(*) from deliveries limit 20"
2026-08-26 13:40:02.370 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Output: "select count(*) from deliveries limit 20" [MATCH]
2026-08-26 13:40:02.372 [main] INFO  c.r.m.s.SafeSqlValidatorTest - Running testCase3_LimitOver100ForcedTo100()...
2026-08-26 13:40:02.375 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Input: "SELECT * FROM deliveries LIMIT 5000"
2026-08-26 13:40:02.378 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Output: "SELECT * FROM deliveries LIMIT 100" [MATCH]
2026-08-26 13:40:02.382 [main] INFO  c.r.m.s.SafeSqlValidatorTest - Running testCase4_NonSelectStatementBlocked()...
2026-08-26 13:40:02.385 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Blocked successfully: SecurityException thrown ("Chỉ cho phép thực thi câu lệnh SELECT tra cứu dữ liệu.")
2026-08-26 13:40:02.388 [main] INFO  c.r.m.s.SafeSqlValidatorTest - Running testCase5_CommentInjectionBlocked()...
2026-08-26 13:40:02.390 [main] INFO  c.r.m.s.SafeSqlValidatorTest - -> Blocked successfully: SecurityException thrown ("Phát hiện ký tự comment SQL nguy hiểm bị cấm.")

[INFO] -------------------------------------------------------
[INFO]  T E S T S   R E S U L T S
[INFO] -------------------------------------------------------
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.125 s -- in com.rikkei.mcp.security.SafeSqlValidatorTest
[INFO] BUILD SUCCESSFUL
```
