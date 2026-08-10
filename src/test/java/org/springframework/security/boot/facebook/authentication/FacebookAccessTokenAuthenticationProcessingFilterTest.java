package org.springframework.security.boot.facebook.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import okhttp3.OkHttpClient;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link FacebookAccessTokenAuthenticationProcessingFilter}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FacebookAccessTokenAuthenticationProcessingFilter Tests")
class FacebookAccessTokenAuthenticationProcessingFilterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OkHttpClient okHttpClient = new OkHttpClient();

    @Test
    @DisplayName("Constructor creates filter with expected defaults")
    void testConstructor() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        assertThat(filter).isNotNull();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("accessToken");
        assertThat(filter.getFields()).containsExactly("id", "name", "gender");
        assertThat(filter.getAlgorithm()).isEqualTo(HmacAlgorithms.HMAC_SHA_256);
        assertThat(filter.getAppSecret()).isNull();
    }

    @Test
    @DisplayName("AUTHORIZATION_PARAM constant has expected value")
    void testAuthorizationParamConstant() {
        assertThat(FacebookAccessTokenAuthenticationProcessingFilter.AUTHORIZATION_PARAM).isEqualTo("accessToken");
    }

    @Test
    @DisplayName("authorizationParamName getter/setter works")
    void testAuthorizationParamName() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        filter.setAuthorizationParamName("fb_token");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("fb_token");
    }

    @Test
    @DisplayName("algorithm getter/setter works")
    void testAlgorithm() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        filter.setAlgorithm(HmacAlgorithms.HMAC_SHA_512);
        assertThat(filter.getAlgorithm()).isEqualTo(HmacAlgorithms.HMAC_SHA_512);
    }

    @Test
    @DisplayName("fields getter/setter works")
    void testFields() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        List<String> fields = Arrays.asList("id", "email", "picture");
        filter.setFields(fields);
        assertThat(filter.getFields()).isEqualTo(fields);
    }

    @Test
    @DisplayName("appSecret getter/setter works")
    void testAppSecret() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        filter.setAppSecret("my_secret");
        assertThat(filter.getAppSecret()).isEqualTo("my_secret");
    }

    @Test
    @DisplayName("obtainAccessToken returns token from request parameter")
    void testObtainAccessToken() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("accessToken", "test_token_123");
        String token = filter.obtainAccessToken(request);
        assertThat(token).isEqualTo("test_token_123");
    }

    @Test
    @DisplayName("obtainAccessToken returns null when parameter is missing")
    void testObtainAccessTokenMissing() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        MockHttpServletRequest request = new MockHttpServletRequest();
        String token = filter.obtainAccessToken(request);
        assertThat(token).isNull();
    }

    @Test
    @DisplayName("obtainAccessToken uses custom parameter name")
    void testObtainAccessTokenCustomParam() {
        FacebookAccessTokenAuthenticationProcessingFilter filter =
                new FacebookAccessTokenAuthenticationProcessingFilter(objectMapper, okHttpClient);
        filter.setAuthorizationParamName("fb_token");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("fb_token", "custom_token");
        String token = filter.obtainAccessToken(request);
        assertThat(token).isEqualTo("custom_token");
    }
}
