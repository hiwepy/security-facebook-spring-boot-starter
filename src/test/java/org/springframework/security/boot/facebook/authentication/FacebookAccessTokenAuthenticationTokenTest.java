package org.springframework.security.boot.facebook.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FacebookAccessTokenAuthenticationToken}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FacebookAccessTokenAuthenticationToken Tests")
class FacebookAccessTokenAuthenticationTokenTest {

    @Test
    @DisplayName("Unauthenticated token stores principal and access token")
    void testUnauthenticatedToken() {
        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken("user123", "fb_token");
        assertThat(token.getPrincipal()).isEqualTo("user123");
        assertThat(token.getCredentials()).isEqualTo("fb_token");
        assertThat(token.getAccessToken()).isEqualTo("fb_token");
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("Authenticated token stores principal, access token, and authorities")
    void testAuthenticatedToken() {
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken(
                "user123", "fb_token", Collections.singletonList(authority));
        assertThat(token.getPrincipal()).isEqualTo("user123");
        assertThat(token.getCredentials()).isEqualTo("fb_token");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("eraseCredentials clears access token")
    void testEraseCredentials() {
        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken("user123", "fb_token");
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
        assertThat(token.getAccessToken()).isNull();
    }

    @Test
    @DisplayName("profile getter/setter works")
    void testProfile() {
        FacebookAccessTokenAuthenticationToken token = new FacebookAccessTokenAuthenticationToken("user123", "fb_token");
        Map<String, String> profile = new HashMap<>();
        profile.put("id", "123");
        profile.put("name", "Test User");
        token.setProfile(profile);
        assertThat(token.getProfile()).isEqualTo(profile);
    }
}
