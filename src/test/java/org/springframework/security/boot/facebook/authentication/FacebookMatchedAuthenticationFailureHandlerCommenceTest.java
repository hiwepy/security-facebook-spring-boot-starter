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
 * Tests for the onAuthenticationFailure method of {@link FacebookMatchedAuthenticationFailureHandler}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FacebookMatchedAuthenticationFailureHandler.onAuthenticationFailure Tests")
class FacebookMatchedAuthenticationFailureHandlerCommenceTest {

    private final FacebookMatchedAuthenticationFailureHandler handler = new FacebookMatchedAuthenticationFailureHandler();

    @Test
    @DisplayName("onAuthenticationFailure writes expired error response")
    void testOnFailureExpired() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new FacebookAccessTokenExpiredException("expired"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentType()).contains("application/json");
    }

    @Test
    @DisplayName("onAuthenticationFailure writes incorrect error response")
    void testOnFailureIncorrect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new FacebookAccessTokenIncorrectException("incorrect"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes invalid error response")
    void testOnFailureInvalid() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new FacebookAccessTokenInvalidException("invalid"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes not-found error response")
    void testOnFailureNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new FacebookAccessTokenNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }
}
