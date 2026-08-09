package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.facebook.authentication.FacebookAuthenticationProvider;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationSuccessHandler;

/**
 * Auto-configuration for Facebook authentication beans.
 * <p>Registers the entry point, failure handler, success handler, and authentication
 * provider required for Facebook access token authentication. This configuration is
 * activated only when {@code spring.security.facebook.enabled=true}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFacebookProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFacebookProperties.class })
public class SecurityFacebookAutoConfiguration {

	/**
	 * Creates a {@link FacebookMatchedAuthenticationEntryPoint} if no existing bean is present.
	 *
	 * @return the authentication entry point for Facebook authentication errors
	 */
	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationEntryPoint facebookMatchedAuthenticationEntryPoint() {
		return new FacebookMatchedAuthenticationEntryPoint();
	}

	/**
	 * Creates a {@link FacebookMatchedAuthenticationFailureHandler} if no existing bean is present.
	 *
	 * @return the authentication failure handler for Facebook authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationFailureHandler facebookMatchedAuthenticationFailureHandler() {
		return new FacebookMatchedAuthenticationFailureHandler();
	}

	/**
	 * Creates a {@link FacebookMatchedAuthenticationSuccessHandler} if no existing bean is present.
	 *
	 * @param payloadRepository the JWT payload repository for generating user profile payloads
	 * @return the authentication success handler for Facebook authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationSuccessHandler facebookMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new FacebookMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	/**
	 * Creates a {@link FacebookAuthenticationProvider} if no existing bean is present.
	 *
	 * @param userDetailsService the user details service adapter for loading user details
	 * @return the authentication provider for Facebook access token authentication
	 */
	@Bean
	@ConditionalOnMissingBean
	public FacebookAuthenticationProvider facebookAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new FacebookAuthenticationProvider(userDetailsService);
	}
	
}
