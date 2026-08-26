package com.rikkei.mcp.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SafeSqlValidatorTest {

    @Test
    public void testCase1_NoLimitAppended() {
        String input = "SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED'";
        String expected = "SELECT id, tracking_code, status FROM deliveries WHERE status = 'DELAYED' LIMIT 100";
        assertEquals(expected, SafeSqlValidator.validateAndSanitize(input));
    }

    @Test
    public void testCase2_LimitUnderOrEqual100Preserved() {
        String input = "select count(*) from deliveries limit 20";
        String expected = "select count(*) from deliveries limit 20";
        assertEquals(expected, SafeSqlValidator.validateAndSanitize(input));
    }

    @Test
    public void testCase3_LimitOver100ForcedTo100() {
        String input = "SELECT * FROM deliveries LIMIT 5000";
        String expected = "SELECT * FROM deliveries LIMIT 100";
        assertEquals(expected, SafeSqlValidator.validateAndSanitize(input));
    }

    @Test
    public void testCase4_NonSelectStatementBlocked() {
        String input = "DROP TABLE deliveries;";
        assertThrows(SecurityException.class, () -> SafeSqlValidator.validateAndSanitize(input));
    }

    @Test
    public void testCase5_CommentInjectionBlocked() {
        String input = "SELECT * FROM deliveries WHERE 1=1 -- delete from deliveries";
        assertThrows(SecurityException.class, () -> SafeSqlValidator.validateAndSanitize(input));
    }
}
