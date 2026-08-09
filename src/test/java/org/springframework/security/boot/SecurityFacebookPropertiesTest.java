package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityFacebookProperties}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityFacebookProperties Tests")
class SecurityFacebookPropertiesTest {

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(SecurityFacebookProperties.PREFIX).isEqualTo("spring.security.facebook");
    }

    @Test
    @DisplayName("Default enabled is false")
    void testDefaultEnabled() {
        SecurityFacebookProperties props = new SecurityFacebookProperties();
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("enabled getter/setter works")
    void testEnabled() {
        SecurityFacebookProperties props = new SecurityFacebookProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("toString returns non-null string")
    void testToString() {
        SecurityFacebookProperties props = new SecurityFacebookProperties();
        assertThat(props.toString()).isNotNull();
    }
}
