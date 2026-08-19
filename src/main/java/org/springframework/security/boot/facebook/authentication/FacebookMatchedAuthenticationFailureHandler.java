package org.springframework.security.boot.facebook.authentication;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.facebook.SpringSecurityFacebookMessageSource;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenExpiredException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenIncorrectException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenInvalidException;
import org.springframework.security.boot.facebook.exception.FacebookAccessTokenNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Authentication failure handler for Facebook authentication errors.
 * <p>Handles Facebook-specific authentication exceptions by writing appropriate
 * JSON error responses with localized messages. Supports expired, incorrect,
 * invalid, and not-found access token exceptions.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class FacebookMatchedAuthenticationFailureHandler implements MatchedAuthenticationFailureHandler {

	protected MessageSourceAccessor messages = SpringSecurityFacebookMessageSource.getAccessor();

	/**
	 * Determines whether supports.
	 *
	 * @param e the e
	 * @return the result
	 */
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), FacebookAccessTokenExpiredException.class,
				FacebookAccessTokenIncorrectException.class, FacebookAccessTokenInvalidException.class,
				FacebookAccessTokenNotFoundException.class );
	}

	/**
	 * on Authentication Failure.
	 *
	 * @param request the request
	 * @param response the response
	 * @param e the e
	 * @throws IOException if an error occurs
	 * @throws ServletException if an error occurs
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());

		if (e instanceof FacebookAccessTokenExpiredException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof FacebookAccessTokenIncorrectException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof FacebookAccessTokenInvalidException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getMsgKey(), e.getMessage())));
		} else if (e instanceof FacebookAccessTokenNotFoundException) {
			JSON.writeTo(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getMsgKey(), e.getMessage())));
		}

	}

}
