package org.springframework.security.boot.facebook.authentication;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenExpiredException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenIncorrectException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenInvalidException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the commence method of {@link FacebookMatchedAuthenticationEntryPoint}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FacebookMatchedAuthenticationEntryPoint.commence Tests")
class FacebookMatchedAuthenticationEntryPointCommenceTest {

    private final FacebookMatchedAuthenticationEntryPoint entryPoint = new FacebookMatchedAuthenticationEntryPoint();

    @Test
    @DisplayName("commence writes expired error response")
    void testCommenceExpired() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new FacebookAccessTokenExpiredException("expired"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentType()).contains("application/json");
    }

    @Test
    @DisplayName("commence writes incorrect error response")
    void testCommenceIncorrect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new FacebookAccessTokenIncorrectException("incorrect"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("commence writes invalid error response")
    void testCommenceInvalid() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new FacebookAccessTokenInvalidException("invalid"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("commence writes not-found error response")
    void testCommenceNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new FacebookAccessTokenNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }
}
