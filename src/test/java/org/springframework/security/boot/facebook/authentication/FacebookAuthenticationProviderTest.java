package org.springframework.security.boot.facebook.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link FacebookAuthenticationProvider}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FacebookAuthenticationProvider Tests")
class FacebookAuthenticationProviderTest {

    @Test
    @DisplayName("Constructor sets userDetailsService")
    void testConstructor() {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        assertThat(provider.getUserDetailsService()).isEqualTo(uds);
    }

    @Test
    @DisplayName("supports FacebookAccessTokenAuthenticationToken")
    void testSupports() {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        assertThat(provider.supports(FacebookAccessTokenAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(Authentication.class)).isFalse();
    }

    @Test
    @DisplayName("authenticate throws on null authentication")
    void testAuthenticateNull() {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("authenticate returns authenticated token")
    void testAuthenticateSuccess() throws Exception {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getAuthorities()).thenReturn(Collections.emptyList());
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isAccountNonExpired()).thenReturn(true);
        when(userDetails.isCredentialsNonExpired()).thenReturn(true);
        when(userDetails.isEnabled()).thenReturn(true);
        when(uds.loadUserDetails(any(Authentication.class))).thenReturn(userDetails);

        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        FacebookAccessTokenAuthenticationToken authRequest = new FacebookAccessTokenAuthenticationToken("user123", "fb_token");
        Authentication result = provider.authenticate(authRequest);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("authenticate returns authenticated token with SecurityPrincipal")
    void testAuthenticateWithSecurityPrincipal() throws Exception {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.getAuthorities()).thenReturn(Collections.emptyList());
        when(principal.isAccountNonLocked()).thenReturn(true);
        when(principal.isAccountNonExpired()).thenReturn(true);
        when(principal.isCredentialsNonExpired()).thenReturn(true);
        when(principal.isEnabled()).thenReturn(true);
        when(uds.loadUserDetails(any(Authentication.class))).thenReturn(principal);

        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        FacebookAccessTokenAuthenticationToken authRequest = new FacebookAccessTokenAuthenticationToken("user123", "fb_token");
        Authentication result = provider.authenticate(authRequest);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        verify(principal).setSign(null);
        verify(principal).setLongitude(0.0);
        verify(principal).setLatitude(0.0);
    }

    @Test
    @DisplayName("userDetailsChecker getter/setter works")
    void testUserDetailsChecker() {
        UserDetailsServiceAdapter uds = mock(UserDetailsServiceAdapter.class);
        FacebookAuthenticationProvider provider = new FacebookAuthenticationProvider(uds);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
        provider.setUserDetailsChecker(null);
        assertThat(provider.getUserDetailsChecker()).isNull();
    }
}
