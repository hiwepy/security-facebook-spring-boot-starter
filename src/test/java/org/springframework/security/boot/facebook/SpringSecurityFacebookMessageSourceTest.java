package org.springframework.security.boot.facebook;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.MessageSourceAccessor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SpringSecurityFacebookMessageSource}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SpringSecurityFacebookMessageSource Tests")
class SpringSecurityFacebookMessageSourceTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        SpringSecurityFacebookMessageSource source = new SpringSecurityFacebookMessageSource();
        assertThat(source).isNotNull();
    }

    @Test
    @DisplayName("getAccessor returns non-null MessageSourceAccessor")
    void testGetAccessor() {
        MessageSourceAccessor accessor = SpringSecurityFacebookMessageSource.getAccessor();
        assertThat(accessor).isNotNull();
    }
}
