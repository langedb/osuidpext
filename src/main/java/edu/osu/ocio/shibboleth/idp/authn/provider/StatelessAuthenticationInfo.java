/*
 * Copyright 2011 The Ohio State University
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.osu.ocio.shibboleth.idp.authn.provider;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.LoginException;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

/**
 * Wraps the encoding of authentication information into and from a string.
 */
public class StatelessAuthenticationInfo {

	/** Client address in textual form. */
	private String address;
	
    /** Identity of user. */
    private String username;

    /** Method of authentication. */
    private String authnMethod;

    /** Time of authentication since the epoch in milliseconds. */
    private long authnInstant;

    /** Additional information tracked about the user. */
    private Map<String, String> resolvedAttributes;

    /** Login context from IdP. */
    private LoginContext loginContext;

    /** Fatal exception during authentication process. */
    private AuthenticationException authnException;

    /** Login exception during authentication process. */
    private LoginException loginException;

    /** Indicates at least one module didn't recognize the username. */
    private boolean unknownUsername;

    /** Indicates at least one module didn't recognize the password. */
    private boolean invalidPassword;

    /** Indicates at least one module detected an expired password. */
    private boolean expiredPassword;

    /** Indicates at least one module detected a disabled account. */
    private boolean accountDisabled;
    
    /** Indicates at least one module detected an account lockout. */
    private boolean accountLocked;
        
    /**
     * Constructor.
     * 
     * @param pickled
     *            raw form of data
     */
    public StatelessAuthenticationInfo(String pickled) {
        String[] values = pickled.split("!", 4);
        address = values[0];
        username = values[1];
        authnMethod = values[2];
        authnInstant = Long.parseLong(values[3]);
    }

    public StatelessAuthenticationInfo() {
    }

    /**
     * Checks the authentication status.
     * 
     * @return true iff authentication has been done
     */
    boolean isAuthenticated() {
        return username != null && authnMethod != null && authnInstant != 0;
    }

    /**
     * Sets the client address of the user.
     * 
     * @param address
     *            the address to set
     */
    public void setAddress(String address) {
        this.address = address;
    }
    
    /**
     * Sets the identity of the user.
     * 
     * @param username
     *            the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Sets the authentication method.
     * 
     * @param authnMethod
     *            the authnMethod to set
     */
    public void setAuthnMethod(String authnMethod) {
        this.authnMethod = authnMethod;
    }

    /**
     * Sets the time of authentication since the epoch in milliseconds.
     * 
     * @param authnInstant
     *            the authnInstant to set
     */
    public void setAuthnInstant(long authnInstant) {
        this.authnInstant = authnInstant;
    }

    /**
     * Sets the LoginContext.
     * 
     * @param loginContext
     *            the loginContext to set
     */
    public void setLoginContext(LoginContext loginContext) {
        this.loginContext = loginContext;
    }

    /**
     * Sets or clears an active authentication error.
     * 
     * @param authnException
     *            the exception to set
     */
    public void setAuthnException(AuthenticationException authnException) {
        this.authnException = authnException;
    }

    /**
     * Sets or clears an active login error.
     * 
     * @param loginException
     *            the exception to set
     */
    public void setLoginException(LoginException loginException) {
        this.loginException = loginException;
    }
    
    /**
     * Sets the unknown username indicator.
     * @param unknownUsername the indicator to set
     */
    public void setUnknownUsername(boolean unknownUsername) {
        this.unknownUsername = unknownUsername;
    }

    /**
     * Sets the invalid password indicator.
     * @param invalidPassword the indicator to set
     */
    public void setInvalidPassword(boolean invalidPassword) {
        this.invalidPassword = invalidPassword;
    }

    /**
     * Sets the expired password indicator.
     * @param expiredPassword the indicator to set 
     */
    public void setExpiredPassword(boolean expiredPassword) {
        this.expiredPassword = expiredPassword;
    }

    /**
     * Sets the account lockout indicator.
     * @param accountLocked the indicator to set 
     */
    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }


    /**
     * Sets the account disabled indicator.
     * @param accountDisabled the indicator to set 
     */
    public void setAccountDisabled(boolean accountDisabled) {
        this.accountDisabled = accountDisabled;
    }
    
    /**
     * Gets the client address of the user.
     * 
     * @return the client address
     */
    public String getAddress() {
        return address;
    }

    /**
     * Gets the identity of the user.
     * 
     * @return the user identity
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the method of authentication.
     * 
     * @return the authentication method
     */
    public String getAuthnMethod() {
        return authnMethod;
    }

    /**
     * Gets the time of authentication since the epoch in milliseconds.
     * 
     * @return the time of authentication
     */
    public long getAuthnInstant() {
        return authnInstant;
    }

    /**
     * Accesses the map of resolved attributes.
     * 
     * @return a map of the resolved attributes
     */
    public Map<String, String> getResolvedAttributes() {
        if (resolvedAttributes == null) {
            resolvedAttributes = new HashMap<String, String>(5);
        }
        return resolvedAttributes;
    }

    /**
     * Gets the LoginContext.
     * 
     * @return the loginContext
     */
    public LoginContext getLoginContext() {
        return loginContext;
    }

    /**
     * Gets the active authentication error, if any.
     * 
     * @return the authentication exception
     */
    public AuthenticationException getAuthnException() {
        return authnException;
    }

    /**
     * Gets the active login error, if any.
     * 
     * @return the login exception
     */
    public LoginException getLoginException() {
        return loginException;
    }
    
    /**
     * Gets the unknown username indicator.
     * @return true iff a module detected an unknown username
     */
    public boolean isUnknownUsername() {
        return unknownUsername;
    }

    /**
     * Gets the invalid password indicator.
     * @return true iff a module detected an invalid password
     */
    public boolean isInvalidPassword() {
        return invalidPassword;
    }

    /**
     * Gets the expired password indicator.
     * @return true iff a module detected an expired password
     */
    public boolean isExpiredPassword() {
        return expiredPassword;
    }

    /**
     * Gets the account lockout indicator.
     * @return true iff a module detected an account lockout
     */
    public boolean isAccountLocked() {
        return accountLocked;
    }

    /**
     * Gets the account lockout indicator.
     * @return true iff a module detected an account lockout
     */
    public boolean isAccountDisabled() {
        return accountDisabled;
    }
        
    /**
     * Gets the encoded form of the information.
     * 
     * @return the encoded authentication data
     */
    public String getPickled() {
        return address + '!' + username + '!' + authnMethod + '!' + Long.toString(authnInstant);
    }

}
