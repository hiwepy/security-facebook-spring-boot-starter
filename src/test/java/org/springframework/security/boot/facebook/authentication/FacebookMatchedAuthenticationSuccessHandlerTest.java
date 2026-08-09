package org.springframework.security.boot.facebook.authentication;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link FacebookMatchedAuthenticationSuccessHandler}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FacebookMatchedAuthenticationSuccessHandler Tests")
class FacebookMatchedAuthenticationSuccessHandlerTest {

    @Test
    @DisplayName("Constructor sets payloadRepository")
    void testConstructor() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        assertThat(handler.getPayloadRepository()).isEqualTo(repository);
    }

    @Test
    @DisplayName("supports FacebookAccessTokenAuthenticationToken")
    void testSupportsToken() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken("user", "token");
        assertThat(handler.supports(token)).isTrue();
    }

    @Test
    @DisplayName("does not support generic Authentication")
    void testDoesNotSupportGeneric() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        Authentication auth = mock(Authentication.class);
        assertThat(handler.supports(auth)).isFalse();
    }

    @Test
    @DisplayName("checkExpiry default is false")
    void testCheckExpiryDefault() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        assertThat(handler.isCheckExpiry()).isFalse();
    }

    @Test
    @DisplayName("checkExpiry getter/setter works")
    void testCheckExpiry() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("payloadRepository getter/setter works")
    void testPayloadRepository() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);
        JwtPayloadRepository newRepo = mock(JwtPayloadRepository.class);
        handler.setPayloadRepository(newRepo);
        assertThat(handler.getPayloadRepository()).isEqualTo(newRepo);
    }

    @Test
    @DisplayName("onAuthenticationSuccess writes response for unbound principal")
    void testOnAuthenticationSuccessUnbound() throws Exception {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);

        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.isBound()).thenReturn(false);
        UserProfilePayload payload = mock(UserProfilePayload.class);
        when(principal.toPayload()).thenReturn(payload);

        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken(
                principal, "fb_token", Collections.emptyList());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, token);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationSuccess writes response for bound principal")
    void testOnAuthenticationSuccessBound() throws Exception {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        UserProfilePayload payload = mock(UserProfilePayload.class);
        when(repository.getProfilePayload(any(), anyBoolean())).thenReturn(payload);

        FacebookMatchedAuthenticationSuccessHandler handler = new FacebookMatchedAuthenticationSuccessHandler(repository);

        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.isBound()).thenReturn(true);

        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken(
                principal, "fb_token", Collections.emptyList());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, token);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }
}
