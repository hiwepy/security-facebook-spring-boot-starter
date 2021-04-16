package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityFacebookProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFacebookProperties {

	public static final String PREFIX = "spring.security.google";

	/** Whether Enable Google AccessToken Authentication. */
	private boolean enabled = false;

}
