package org.springframework.security.boot.facebook.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Facebook exception classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("Facebook Exception Tests")
class FacebookExceptionTest {

    @Test
    @DisplayName("FacebookAccessTokenExpiredException single-arg constructor")
    void testExpiredExceptionMessage() {
        FacebookAccessTokenExpiredException ex = new FacebookAccessTokenExpiredException("token expired");
        assertThat(ex.getMessage()).isEqualTo("token expired");
    }

    @Test
    @DisplayName("FacebookAccessTokenExpiredException two-arg constructor")
    void testExpiredExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        FacebookAccessTokenExpiredException ex = new FacebookAccessTokenExpiredException("token expired", cause);
        assertThat(ex.getMessage()).isEqualTo("token expired");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("FacebookAccessTokenIncorrectException single-arg constructor")
    void testIncorrectExceptionMessage() {
        FacebookAccessTokenIncorrectException ex = new FacebookAccessTokenIncorrectException("incorrect token");
        assertThat(ex.getMessage()).isEqualTo("incorrect token");
    }

    @Test
    @DisplayName("FacebookAccessTokenIncorrectException two-arg constructor")
    void testIncorrectExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        FacebookAccessTokenIncorrectException ex = new FacebookAccessTokenIncorrectException("incorrect token", cause);
        assertThat(ex.getMessage()).isEqualTo("incorrect token");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("FacebookAccessTokenInvalidException single-arg constructor")
    void testInvalidExceptionMessage() {
        FacebookAccessTokenInvalidException ex = new FacebookAccessTokenInvalidException("invalid token");
        assertThat(ex.getMessage()).isEqualTo("invalid token");
    }

    @Test
    @DisplayName("FacebookAccessTokenInvalidException two-arg constructor")
    void testInvalidExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        FacebookAccessTokenInvalidException ex = new FacebookAccessTokenInvalidException("invalid token", cause);
        assertThat(ex.getMessage()).isEqualTo("invalid token");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("FacebookAccessTokenNotFoundException single-arg constructor")
    void testNotFoundExceptionMessage() {
        FacebookAccessTokenNotFoundException ex = new FacebookAccessTokenNotFoundException("token not found");
        assertThat(ex.getMessage()).isEqualTo("token not found");
    }

    @Test
    @DisplayName("FacebookAccessTokenNotFoundException two-arg constructor")
    void testNotFoundExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        FacebookAccessTokenNotFoundException ex = new FacebookAccessTokenNotFoundException("token not found", cause);
        assertThat(ex.getMessage()).isEqualTo("token not found");
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
