package org.springframework.security.boot.facebook.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FacebookAccessTokenLoginRequest}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FacebookAccessTokenLoginRequest Tests")
class FacebookAccessTokenLoginRequestTest {

    @Test
    @DisplayName("Constructor sets accessToken")
    void testConstructor() {
        FacebookAccessTokenLoginRequest request = new FacebookAccessTokenLoginRequest("my_token");
        assertThat(request.getAccessToken()).isEqualTo("my_token");
    }

    @Test
    @DisplayName("accessToken getter/setter works")
    void testAccessToken() {
        FacebookAccessTokenLoginRequest request = new FacebookAccessTokenLoginRequest("old_token");
        request.setAccessToken("new_token");
        assertThat(request.getAccessToken()).isEqualTo("new_token");
    }
}
