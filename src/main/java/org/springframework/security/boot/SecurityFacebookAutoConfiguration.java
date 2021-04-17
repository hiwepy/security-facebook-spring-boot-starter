package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationFailureHandler;

import okhttp3.OkHttpClient;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFacebookProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFacebookProperties.class })
public class SecurityFacebookAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(OkHttpClient.class)
	public OkHttpClient okhttp3Client() {
		return new OkHttpClient().newBuilder().build();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationEntryPoint googleMatchedAuthenticationEntryPoint() {
		return new FacebookMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public FacebookMatchedAuthenticationFailureHandler googleMatchedAuthenticationFailureHandler() {
		return new FacebookMatchedAuthenticationFailureHandler();
	}

}
