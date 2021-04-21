package org.springframework.security.boot.facebook.authentication;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.facebook.SpringSecurityFacebookMessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FacebookAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityFacebookMessageSource.getAccessor();
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public FacebookAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (FacebookAccessTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (log.isDebugEnabled()) {
    		log.debug("Processing authentication request : " + authentication);
		}
    	
    	FacebookAccessTokenAuthenticationToken token = (FacebookAccessTokenAuthenticationToken) authentication;
        
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        FacebookAccessTokenAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	SecurityPrincipal principal = (SecurityPrincipal) ud;
        	principal.setSign(token.getSign());
    		principal.setLongitude(token.getLongitude());
    		principal.setLatitude(token.getLatitude());
        	authenticationToken = new FacebookAccessTokenAuthenticationToken(ud, token.getAccessToken(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new FacebookAccessTokenAuthenticationToken(token.getPrincipal(), token.getAccessToken(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
