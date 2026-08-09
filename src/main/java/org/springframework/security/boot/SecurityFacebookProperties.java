package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Top-level configuration properties for Facebook authentication.
 * <p>Binds to the {@code spring.security.facebook} prefix and controls whether
 * Facebook access token authentication is enabled.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecurityFacebookProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFacebookProperties {

	public static final String PREFIX = "spring.security.facebook";

	/** Whether Enable Facebook AccessToken Authentication. */
	private boolean enabled = false;

}
