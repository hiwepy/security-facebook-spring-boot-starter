package org.springframework.security.boot.facebook.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Facebook AccessToken 登录认证绑定的参数对象Model
 * 
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class FacebookAccessTokenLoginRequest {

	/**
	 * Google AccessToken
	 */
	private String accessToken;

	@JsonCreator
	public FacebookAccessTokenLoginRequest(@JsonProperty("accessToken") String accessToken) {
		this.accessToken = accessToken;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
