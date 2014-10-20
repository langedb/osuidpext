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

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.jaas.securid.SecurIDPrincipal;

/**
 * Submodule that validates credentials using JAAS.
 */
public class JAASLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(JAASLoginSubmodule.class);

    /** Name of JAAS configuration used to authenticate users. */
    private String jaasConfigName = "ShibUserPassAuth";

    /** Supported authentication methods. */
    private Set<String> authnMethods = new HashSet<String>();
    
    /** Error messages indicating an unknown username. */
    private List<String> unknownUsernameErrors = new ArrayList<String>();

    /** Error messages indicating an invalid password. */
    private List<String> invalidPasswordErrors = new ArrayList<String>();

    /** Error messages indicating an expired password. */
    private List<String> expiredPasswordErrors = new ArrayList<String>();

    /** Messages indicating a locked account. */
    private List<String> accountLockedErrors = new ArrayList<String>();

    /** Messages indicating a disabled account. */
    private List<String> accountDisabledErrors = new ArrayList<String>();
    
    /**
     * Constructor.
     * 
     * @param jaasConfigLocation    path to JAAS config
     */
    JAASLoginSubmodule(String jaasConfigLocation) {
        if (jaasConfigLocation != null) {
            log.debug("Setting JAAS configuration file to: {}", jaasConfigLocation);
            System.setProperty("java.security.auth.login.config", jaasConfigLocation);        
        }
    }

    /**
     * Gets the JAAS config name.
     * @return the JAAS config name
     */
    public String getJaasConfigName() {
        return jaasConfigName;
    }
    
    /**
     * Gets the supported authentication methods.
     * @return the supported authn methods
     */
    public Set<String> getAuthnMethods() {
        return authnMethods;
    }

    /**
     * Get the error messages indicating an unknown username.
     * @return the "unknown username" error messages
     */
    public List<String> getUnknownUsernameErrors() {
        return unknownUsernameErrors;
    }
    

    /**
     * Get the error messages indicating an invalid password.
     * @return the "invalid password" error messages
     */
    public List<String> getInvalidPasswordErrors() {
        return invalidPasswordErrors;
    }
    

    /**
     * Get the error messages indicating an expired password.
     * @return the "expired password" error messages
     */
    public List<String> getExpiredPasswordErrors() {
        return expiredPasswordErrors;
    }
    

    /**
     * Get the error messages indicating a locked account.
     * @return the "account locked" error messages
     */
    public List<String> getAccountLockedErrors() {
        return accountLockedErrors;
    }

    /**
     * Get the error messages indicating a disabled account.
     * @return the "account disabled" error messages
     */
    public List<String> getAccountDisabledErrors() {
        return accountDisabledErrors;
    }
    
    /**
     * Sets the JAAS config name.
     * @param jaasConfigName the JAAS config name to set
     */
    public void setJaasConfigName(String jaasConfigName) {
        this.jaasConfigName = jaasConfigName;
    }
    

    /**
     * Sets the supported authentication methods.
     * @param authnMethods the authn methods to set
     */
    public void setAuthnMethods(Set<String> authnMethods) {
        this.authnMethods = authnMethods;
    }
    
    /**
     * Sets the error messages indicating an unknown username.
     * @param unknownUsernameErrors the "unknown username" error messages to set
     */
    public void setUnknownUsernameErrors(List<String> unknownUsernameErrors) {
        this.unknownUsernameErrors = unknownUsernameErrors;
    }
    

    /**
     * Sets the error messages indicating an invalid password.
     * @param invalidPasswordErrors the "invalid password" error messages to set
     */
    public void setInvalidPasswordErrors(List<String> invalidPasswordErrors) {
        this.invalidPasswordErrors = invalidPasswordErrors;
    }
    

    /**
     * Sets the error messages indicating an expired password.
     * @param expiredPasswordErrors the "expired password" error messages to set
     */
    public void setExpiredPasswordErrors(List<String> expiredPasswordErrors) {
        this.expiredPasswordErrors = expiredPasswordErrors;
    }
    

    /**
     * Sets the error messages indicating a locked account.
     * @param accountLockedErrors the "account locked" error messages to set
     */
    public void setAccountLockedErrors(List<String> accountLockedErrors) {
        this.accountLockedErrors = accountLockedErrors;
    }
    
    /**
     * Sets the error messages indicating a disabled account.
     * @param accountDisabledErrors the "account disabled" error messages to set
     */
    public void setAccountDisabledErrors(List<String> accountDisabledErrors) {
        this.accountDisabledErrors = accountDisabledErrors;
    }

    /**
     * Authenticate a username and password against JAAS. If authentication succeeds,
     * the resulting Subject is returned.
     * 
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     * @return  the authenticated Subject
     * @throws LoginException thrown if there is a problem authenticating the user
     */
    private Subject authenticateUser(String username, String password) throws LoginException {
        try {
            log.debug("Attempting to authenticate user {}", username);

            SimpleCallbackHandler cbh = new SimpleCallbackHandler(username, password);

            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    jaasConfigName, cbh);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);

            return jaasLoginCtx.getSubject();
        } catch (LoginException e) {
            log.info("User authentication for {} failed: {}", username, e.getMessage());
            throw e;
        } catch (Throwable e) {
            log.info("User authentication for {} failed: {}", username, e.getMessage());
            throw new LoginException(e.getMessage());
        }
    }

    /**
     * A callback handler that provides static name and password data to a JAAS loging process.
     * 
     * This handler only supports {@link NameCallback} and {@link PasswordCallback}.
     */
    protected class SimpleCallbackHandler implements CallbackHandler {

        /** Name of the user. */
        private String uname;

        /** User's password. */
        private String pass;

        /**
         * Constructor.
         * 
         * @param username The username
         * @param password The password
         */
        public SimpleCallbackHandler(String username, String password) {
            uname = username;
            pass = password;
        }

        /**
         * Handle a callback.
         * 
         * @param callbacks The list of callbacks to process.
         * 
         * @throws UnsupportedCallbackException If callbacks has a callback other than {@link NameCallback} or
         *             {@link PasswordCallback}.
         */
        public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {

            if (callbacks == null || callbacks.length == 0) {
                return;
            }

            for (Callback cb : callbacks) {
                if (cb instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) cb;
                    ncb.setName(uname);
                } else if (cb instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) cb;
                    pcb.setPassword(pass.toCharArray());
                }
            }
        }
    }

    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request, HttpServletResponse response,
            StatelessAuthenticationInfo info) throws AuthenticationException, LoginException {

        if (info.isAuthenticated()) {
            return;
        }
        
        List<String> requestedMethods = info.getLoginContext().getRequestedAuthenticationMethods();
        
        if (requestedMethods != null && !requestedMethods.isEmpty()) {
            boolean supported = false;
            for (String m : requestedMethods) {
                if (authnMethods.contains(m)) {
                    supported = true;
                    break;
                }
            }
            if (!supported) {
                log.debug("Requested authentication method(s) not supported by {}.", jaasConfigName);
                return;
            }
        }
    
        String u = request.getParameter("j_username");
        String p = request.getParameter("j_password");
        
        if (u != null && !u.isEmpty()) {
            if (p == null || p.isEmpty()) {
                info.setInvalidPassword(true);
                return;
            }
            
            u = u.toLowerCase();
            int pos = u.indexOf("@osu.edu");
            if (pos > 0) {
            	u = u.substring(0, pos);
            }

            try {
                Subject loginSubject = authenticateUser(u, p);
                info.setUsername(u);
                Set<Principal> principals = loginSubject.getPrincipals();
                String method = AuthnContext.PPT_AUTHN_CTX;
                for (Principal principal : principals) {
                    if (principal instanceof SecurIDPrincipal) {
                        method = AuthnContext.TIME_SYNC_TOKEN_AUTHN_CTX;
                        break;
                    }
                }
                info.setAuthnMethod(method);
                info.setAuthnInstant(System.currentTimeMillis());
            } catch (LoginException e) {
                for (String m : unknownUsernameErrors) {
                    if (e.getMessage().contains(m)) {
                        log.info("Unknown username error in module {}.", jaasConfigName);
                        info.setUnknownUsername(true);
                        return;
                    }
                }

                for (String m : invalidPasswordErrors) {
                    if (e.getMessage().contains(m)) {
                        log.info("Invalid password error in module {}.", jaasConfigName);
                        info.setInvalidPassword(true);
                        return;
                    }
                }

                for (String m : expiredPasswordErrors) {
                    if (e.getMessage().contains(m)) {
                        log.info("Expired password error in module {}.", jaasConfigName);
                        info.setExpiredPassword(true);
                        return;
                    }
                }


                for (String m : accountDisabledErrors) {
                    if (e.getMessage().contains(m)) {
                        log.info("Disabled account error in module {}.", jaasConfigName);
                        info.setAccountDisabled(true);
                        return;
                    }
                }
                
                for (String m : accountLockedErrors) {
                    if (e.getMessage().contains(m)) {
                        log.info("Locked account error in module {}.", jaasConfigName);
                        info.setAccountLocked(true);
                        return;
                    }
                }
                
                throw e;
            }
        }
    }
}