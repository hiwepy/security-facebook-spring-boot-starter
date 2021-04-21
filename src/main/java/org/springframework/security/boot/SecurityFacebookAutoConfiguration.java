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

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFacebookProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFacebookProperties.class })
public class SecurityFacebookAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationEntryPoint facebookMatchedAuthenticationEntryPoint() {
		return new FacebookMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationFailureHandler facebookMatchedAuthenticationFailureHandler() {
		return new FacebookMatchedAuthenticationFailureHandler();
	}

	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationSuccessHandler facebookMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new FacebookMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public FacebookAuthenticationProvider facebookAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new FacebookAuthenticationProvider(userDetailsService);
	}
	
}
