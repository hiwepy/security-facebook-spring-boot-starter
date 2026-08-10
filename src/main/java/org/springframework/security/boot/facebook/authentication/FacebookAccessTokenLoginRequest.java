package org.springframework.security.boot.facebook.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model binding the Facebook access token for login authentication.
 * <p>Deserialized from the JSON request body when the client submits a Facebook
 * access token for authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class FacebookAccessTokenLoginRequest {

	/**
	 * Facebook access token.
	 */
	private String accessToken;

	/**
	 * Constructs a new login request with the given access token.
	 *
	 * @param accessToken the Facebook access token
	 */
	@JsonCreator
	public FacebookAccessTokenLoginRequest(@JsonProperty("accessToken") String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Returns the Facebook access token.
	 *
	 * @return the access token
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Sets the Facebook access token.
	 *
	 * @param accessToken the access token
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
