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

import java.util.Collection;
import java.util.Map;

import org.springframework.security.boot.biz.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class FacebookAuthenticationToken extends AbstractAuthenticationToken {

	private String accessToken;
	private Map<String, String> profile;
    
    public FacebookAuthenticationToken( Object principal, Map<String, String> profile, String accessToken) {
        super(principal);
        this.profile = profile;
        this.accessToken = accessToken;
    }

    public FacebookAuthenticationToken( Object principal, Map<String, String> profile, String accessToken, Collection<? extends GrantedAuthority> authorities) {
        super(principal, null, authorities);
        this.profile = profile;
        this.accessToken = accessToken;
    }
    
    @Override
    public Object getCredentials() {
        return accessToken;
    }
    
    @Override
    public void eraseCredentials() {        
        super.eraseCredentials();
        this.accessToken = null;
    }
	
	public Map<String, String> getProfile() {
		return profile;
	}
    
	public String getAccessToken() {
		return accessToken;
	}
    
}
