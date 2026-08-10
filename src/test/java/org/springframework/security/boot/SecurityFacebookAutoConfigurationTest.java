package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.facebook.authentication.FacebookAuthenticationProvider;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link SecurityFacebookAutoConfiguration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityFacebookAutoConfiguration Tests")
class SecurityFacebookAutoConfigurationTest {

    private final SecurityFacebookAutoConfiguration config = new SecurityFacebookAutoConfiguration();

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        assertThat(config).isNotNull();
    }

    @Test
    @DisplayName("facebookMatchedAuthenticationEntryPoint bean is created")
    void testEntryPoint() {
        FacebookMatchedAuthenticationEntryPoint entryPoint = config.facebookMatchedAuthenticationEntryPoint();
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("facebookMatchedAuthenticationFailureHandler bean is created")
    void testFailureHandler() {
        FacebookMatchedAuthenticationFailureHandler handler = config.facebookMatchedAuthenticationFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("facebookMatchedAuthenticationSuccessHandler bean is created")
    void testSuccessHandler() {
        JwtPayloadRepository repository = mock(JwtPayloadRepository.class);
        FacebookMatchedAuthenticationSuccessHandler handler = config.facebookMatchedAuthenticationSuccessHandler(repository);
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("facebookAuthenticationProvider bean is created")
    void testAuthenticationProvider() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        FacebookAuthenticationProvider provider = config.facebookAuthenticationProvider(userDetailsService);
        assertThat(provider).isNotNull();
    }
}
