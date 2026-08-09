/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.facebook.authentication;

import org.springframework.security.boot.biz.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

/**
 * Authentication token representing a Facebook access token credential.
 * <p>Stores the Facebook access token and optional user profile data retrieved
 * from the Facebook Graph API. Used throughout the authentication flow to carry
 * the principal and granted authorities.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class FacebookAccessTokenAuthenticationToken extends AbstractAuthenticationToken {

	private String accessToken;
	private Map<String, String> profile;
    
    /**
     * Constructs an unauthenticated token with the given principal and access token.
     *
     * @param principal the principal (typically a user ID)
     * @param accessToken the Facebook access token
     */
    public FacebookAccessTokenAuthenticationToken( Object principal, String accessToken) {
        super(principal);
        this.accessToken = accessToken;
    }

    /**
     * Constructs an authenticated token with the given principal, access token, and authorities.
     *
     * @param principal the principal (typically a user details object)
     * @param accessToken the Facebook access token
     * @param authorities the granted authorities
     */
    public FacebookAccessTokenAuthenticationToken( Object principal, String accessToken, Collection<? extends GrantedAuthority> authorities) {
        super(principal, null, authorities);
        this.accessToken = accessToken;
    }

    /**
     * {@inheritDoc}
     * <p>Returns the Facebook access token as the credential.</p>
     */
    @Override
    public Object getCredentials() {
        return accessToken;
    }

    /**
     * {@inheritDoc}
     * <p>Erases the access token for security purposes.</p>
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.accessToken = null;
    }

	/**
	 * Returns the user profile data retrieved from the Facebook Graph API.
	 *
	 * @return a map of profile field names to values
	 */
	public Map<String, String> getProfile() {
		return profile;
	}

	/**
	 * Sets the user profile data retrieved from the Facebook Graph API.
	 *
	 * @param profile a map of profile field names to values
	 */
	public void setProfile(Map<String, String> profile) {
		this.profile = profile;
	}

	/**
	 * Returns the Facebook access token.
	 *
	 * @return the access token
	 */
	public String getAccessToken() {
		return accessToken;
	}
    
}
