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
package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.facebook.authentication.FacebookAccessTokenAuthenticationProcessingFilter;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration properties for Facebook access token authentication.
 * <p>Binds to the {@code spring.security.facebook.authc} prefix and extends
 * the common authentication properties with Facebook-specific settings such as
 * HMAC algorithm, requested profile fields, and application secret.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@ConfigurationProperties(SecurityFacebookAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFacebookAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.facebook.authc";

	/** Authorization path pattern. */
	private String pathPattern = "/**";

	/** The token parameter name. Defaults to "token". */
	private String authorizationParamName = FacebookAccessTokenAuthenticationProcessingFilter.AUTHORIZATION_PARAM;

	/** HMAC algorithm used to generate the {@code appsecret_proof} for Facebook Graph API requests. */
	private HmacAlgorithms algorithm;

	/** List of Facebook profile fields to request (e.g. {@code id}, {@code name}, {@code gender}). */
	private List<String> fields = Arrays.asList("id","name","gender");

	/** Facebook application secret used to compute the {@code appsecret_proof}. */
	private String appSecret;

}
