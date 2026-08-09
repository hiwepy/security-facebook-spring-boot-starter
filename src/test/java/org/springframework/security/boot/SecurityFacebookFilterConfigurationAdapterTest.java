package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityFacebookFilterConfiguration}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityFacebookFilterConfiguration Inner Classes Tests")
class SecurityFacebookFilterConfigurationAdapterTest {

    @Test
    @DisplayName("SecurityFacebookFilterConfiguration has expected inner class")
    void testInnerClassExists() {
        Class<?>[] innerClasses = SecurityFacebookFilterConfiguration.class.getDeclaredClasses();
        assertThat(innerClasses).isNotEmpty();
        boolean found = false;
        for (Class<?> clazz : innerClasses) {
            if (clazz.getSimpleName().equals("FacebookWebSecurityCustomizerAdapter")) {
                found = true;
                break;
            }
        }
        assertThat(found).isTrue();
    }
}
