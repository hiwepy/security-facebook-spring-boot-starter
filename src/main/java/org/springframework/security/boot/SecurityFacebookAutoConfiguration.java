package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.facebook.authentication.FacebookMatchedAuthenticationFailureHandler;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFacebookProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFacebookProperties.class })
public class SecurityFacebookAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public HttpTransport transport() {
		return new NetHttpTransport();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JsonFactory jsonFactory() {
		return new GsonFactory();
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
