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
