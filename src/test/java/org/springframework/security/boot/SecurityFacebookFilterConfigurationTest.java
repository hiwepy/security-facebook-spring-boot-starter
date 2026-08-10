package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityFacebookFilterConfiguration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityFacebookFilterConfiguration Tests")
class SecurityFacebookFilterConfigurationTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        SecurityFacebookFilterConfiguration config = new SecurityFacebookFilterConfiguration();
        assertThat(config).isNotNull();
    }
}
