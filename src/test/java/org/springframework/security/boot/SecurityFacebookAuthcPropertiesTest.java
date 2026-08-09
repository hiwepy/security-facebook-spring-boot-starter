package org.springframework.security.boot;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityFacebookAuthcProperties}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityFacebookAuthcProperties Tests")
class SecurityFacebookAuthcPropertiesTest {

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(SecurityFacebookAuthcProperties.PREFIX).isEqualTo("spring.security.facebook.authc");
    }

    @Test
    @DisplayName("Default values are correct")
    void testDefaultValues() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        assertThat(props.getPathPattern()).isEqualTo("/**");
        assertThat(props.getAuthorizationParamName()).isEqualTo("accessToken");
        assertThat(props.getFields()).containsExactly("id", "name", "gender");
        assertThat(props.getAlgorithm()).isNull();
        assertThat(props.getAppSecret()).isNull();
    }

    @Test
    @DisplayName("pathPattern getter/setter works")
    void testPathPattern() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        props.setPathPattern("/facebook/**");
        assertThat(props.getPathPattern()).isEqualTo("/facebook/**");
    }

    @Test
    @DisplayName("authorizationParamName getter/setter works")
    void testAuthorizationParamName() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        props.setAuthorizationParamName("fb_token");
        assertThat(props.getAuthorizationParamName()).isEqualTo("fb_token");
    }

    @Test
    @DisplayName("algorithm getter/setter works")
    void testAlgorithm() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        props.setAlgorithm(HmacAlgorithms.HMAC_SHA_256);
        assertThat(props.getAlgorithm()).isEqualTo(HmacAlgorithms.HMAC_SHA_256);
    }

    @Test
    @DisplayName("fields getter/setter works")
    void testFields() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        List<String> fields = Arrays.asList("id", "email");
        props.setFields(fields);
        assertThat(props.getFields()).isEqualTo(fields);
    }

    @Test
    @DisplayName("appSecret getter/setter works")
    void testAppSecret() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        props.setAppSecret("my_secret");
        assertThat(props.getAppSecret()).isEqualTo("my_secret");
    }

    @Test
    @DisplayName("toString returns non-null string")
    void testToString() {
        SecurityFacebookAuthcProperties props = new SecurityFacebookAuthcProperties();
        assertThat(props.toString()).isNotNull();
    }
}
