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

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;

/**
 * Submodule that supports a dummy username/password combination for testing.
 */
public class DummyLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DummyLoginSubmodule.class);
    
    /** Name of dummy user. */
    private String username;

    /** Value of dummy password. */
    private String password;
    
    /**
     * Gets the dummy username.
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the dummy password.
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the dummy username.
     * @param u the username to set
     */
    public void setUsername(String u) {
        username = u;
    }

    /**
     * Sets the dummy password.
     * @param p the password to set
     */
    public void setPassword(String p) {
        password = p;
    }

    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response, StatelessAuthenticationInfo info) throws AuthenticationException {

        if (info.isAuthenticated()) {
            return;
        }
        
        List<String> requestedMethods = info.getLoginContext().getRequestedAuthenticationMethods();
        if (requestedMethods != null && !requestedMethods.isEmpty() &&
                !requestedMethods.contains(AuthnContext.PPT_AUTHN_CTX)) {
            log.debug("Request does not allow for password-based authn.");
            return;
        }

        String u = request.getParameter("j_username");
        String p = request.getParameter("j_password");
        
        if (u != null) {
            if (!u.equals(username)) {
                info.setUnknownUsername(true);
                return;
            } else if (p == null || !p.equals(password)) {
                info.setInvalidPassword(true);
                return;
            }
            
            log.info("successfully authenticated user {}", u);
            info.setUsername(u);
            info.setAuthnMethod(AuthnContext.PPT_AUTHN_CTX);
            info.setAuthnInstant(System.currentTimeMillis());
        }
    }

}
