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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.AuthenticationProcessingFilter;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenExpiredException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenIncorrectException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Facebook 登录授权 (authorization)过滤器
 */
@Slf4j
public class FacebookAccessTokenAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

    private static String GET_USER_INFO_URL = "https://graph.facebook.com/v7.0/me";
	/**
	 * HTTP Authorization Param, equal to <code>accessToken</code>
	 */
	public static final String AUTHORIZATION_PARAM = "accessToken";
	private ObjectMapper objectMapper = new ObjectMapper();
	private String authorizationParamName = AUTHORIZATION_PARAM;
    private OkHttpClient okhttp3Client;
	private HmacAlgorithms algorithm = HmacAlgorithms.HMAC_SHA_256;
	private List<String> fields;
	private String appSecret;
	
    public FacebookAccessTokenAuthenticationProcessingFilter(ObjectMapper objectMapper, OkHttpClient okhttp3Client) {
    	super(new AntPathRequestMatcher("/login/facebook"));
    	this.objectMapper = objectMapper;
    	this.okhttp3Client = okhttp3Client;
    	this.fields = Arrays.asList("id","name","gender");
    }

    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
 
    	String accessToken = "";
    	
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			FacebookAccessTokenLoginRequest loginRequest = objectMapper.readValue(request.getReader(), FacebookAccessTokenLoginRequest.class);
			accessToken = loginRequest.getAccessToken();
		} else {
			accessToken = this.obtainAccessToken(request);
		}
		if (accessToken == null) {
			accessToken = "";
		}
		accessToken = accessToken.trim();
		
		if(StringUtils.isBlank(accessToken)) {
			throw new FacebookAccessTokenNotFoundException("accessToken not provided");
		}
		
		long start = System.currentTimeMillis();
		String uidString = null;
		Map<String, String> profile = new HashMap<String, String>();
		try {
			
			if(!fields.contains("id")) {
				fields.add(0, "id");
			}
            HttpUrl.Builder urlBuilder = HttpUrl.parse(GET_USER_INFO_URL).newBuilder();
            urlBuilder.addQueryParameter("fields", StringUtils.join(fields , ","));
            urlBuilder.addQueryParameter("access_token", accessToken);
            urlBuilder.addQueryParameter("appsecret_proof", new HmacUtils(algorithm, appSecret).hmacHex(accessToken));

            Request request1 = new Request.Builder().url(urlBuilder.build()).build();
            Response response1 = okhttp3Client.newCall(request1).execute();
            if (response1.isSuccessful()) {
                String content = response1.body().string();
                log.debug("Request Success: code : {}, body : {} , use time : {} ", response1.code(), content, System.currentTimeMillis() - start);
                JSONObject jsonObject = JSONObject.parseObject(content);
                if (jsonObject.getJSONObject("error") != null) {
                    System.out.println(jsonObject.getJSONObject("error"));
                    throw new FacebookAccessTokenExpiredException(jsonObject.getJSONObject("error").getString("message"));
                }
                uidString = jsonObject.getString("id");
                for (String field : fields) {
                	profile.put(field, jsonObject.getString(field));
				}
            }
            
        } catch (Exception e) {
            log.error("Request Failure : {}, use time : {} ", e.getMessage(), System.currentTimeMillis() - start);
            throw new FacebookAccessTokenIncorrectException(" Google Id Token Invalid ");
        }
		
		FacebookAccessTokenAuthenticationToken authRequest = new FacebookAccessTokenAuthenticationToken(uidString, profile, accessToken);
		authRequest.setAppId(this.obtainAppId(request));
		authRequest.setAppChannel(this.obtainAppChannel(request));
		authRequest.setAppVersion(this.obtainAppVersion(request));
		authRequest.setUid(this.obtainUid(request));
		authRequest.setLongitude(this.obtainLongitude(request));
		authRequest.setLatitude(this.obtainLatitude(request));
		authRequest.setSign(this.obtainSign(request));
		
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }
    
	protected String obtainAccessToken(HttpServletRequest request) {
		// 从参数中获取token
		String token = request.getParameter(getAuthorizationParamName());
		return token;
	}

	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}
	
	public HmacAlgorithms getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(HmacAlgorithms algorithm) {
		this.algorithm = algorithm;
	}

	public List<String> getFields() {
		return fields;
	}

	public void setFields(List<String> fields) {
		this.fields = fields;
	}

	public String getAppSecret() {
		return appSecret;
	}

	public void setAppSecret(String appSecret) {
		this.appSecret = appSecret;
	}
 
	

}