package org.springframework.security.boot.facebook.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenExpiredException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenIncorrectException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenInvalidException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FacebookMatchedAuthenticationFailureHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FacebookMatchedAuthenticationFailureHandler Tests")
class FacebookMatchedAuthenticationFailureHandlerTest {

    private final FacebookMatchedAuthenticationFailureHandler handler = new FacebookMatchedAuthenticationFailureHandler();

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("supports FacebookAccessTokenExpiredException")
    void testSupportsExpired() {
        assertThat(handler.supports(new FacebookAccessTokenExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports FacebookAccessTokenIncorrectException")
    void testSupportsIncorrect() {
        assertThat(handler.supports(new FacebookAccessTokenIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports FacebookAccessTokenInvalidException")
    void testSupportsInvalid() {
        assertThat(handler.supports(new FacebookAccessTokenInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("supports FacebookAccessTokenNotFoundException")
    void testSupportsNotFound() {
        assertThat(handler.supports(new FacebookAccessTokenNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("does not support generic AuthenticationException")
    void testDoesNotSupportGeneric() {
        assertThat(handler.supports(new AuthenticationException("generic") {})).isFalse();
    }
}
