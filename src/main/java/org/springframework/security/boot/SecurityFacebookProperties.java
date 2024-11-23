package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityFacebookProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFacebookProperties {

	public static final String PREFIX = "spring.security.facebook";

	/** Whether Enable Facebook AccessToken Authentication. */
	private boolean enabled = false;

}
