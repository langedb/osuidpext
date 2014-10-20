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

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;

/**
 * Implemented by submodules of the {@link StatelessLoginServlet} that process
 * credentials or render a user interface.
 */
public interface StatelessLoginSubmodule {

    /**
     * Performs an authentication or UI function on behalf of the
     * {@link StatelessLoginServlet}.
     * 
     * @param servlet
     *            the servlet running the request
     * @param request
     *            the client's request
     * @param response
     *            the response to the client
     * @param info
     *            an object for describing the result of a successful act of
     *              authentication
     * @throws AuthenticationException
     *            raised if a fatal error occurs
     * @throws LoginException
     * 			  raised if a login-related error occurs 
     */
    void run(StatelessLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response, StatelessAuthenticationInfo info)
    	throws AuthenticationException, LoginException;

}
