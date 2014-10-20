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

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.datatype.Duration;

import org.joda.time.DateTime;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.PassiveAuthenticationException;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import edu.internet2.middleware.shibboleth.common.util.DataExpiredException;
import edu.internet2.middleware.shibboleth.common.util.DataSealer;
import edu.internet2.middleware.shibboleth.common.util.DataSealerException;

/**
 * Authenticate a username and password against OSU enterprise sources, tracking
 * previous logins with a client-side cookie.
 */
public class StatelessLoginServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956991L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(StatelessLoginServlet.class);

    /** The name of the cookie for tracking user sessions. */
    private String cookieName = "_osu_idp_sso";

    /** Error page to use for unrecoverable errors. */
    private String errorPage = "/statelessError.jsp";
    
    /** Foreign servlet context for error page. */
    private String errorContext;

    /** Lifetime of authentication in milliseconds. */
    private long lifetime = 1000 * 60 * 60 * 8;

    /** Object used to protect SSO cookie. */
    private DataSealer dataSealer;

    /** Ordered list of submodules to use. */
    private String[] submodules;
    
    /** Map of submodule ID to submodule. */
    private HashMap<String, StatelessLoginSubmodule> submoduleMap;

    /** init-param which can be passed to the servlet to override the default cookie name. */
    private final String cookieNameInitParam = "cookieName";

    /** init-param which can be passed to the servlet to override the default error page. */
    private final String errorPageInitParam = "errorPage";

    /** init-param which can be passed to the servlet to override the default error context. */
    private final String errorContextInitParam = "errorContext";

    /** init-param which can be passed to the servlet to override the default lifetime. */
    private final String lifetimeInitParam = "lifetime";

    /** init-param which can be passed to the servlet to override the DataSealer bean id. */
    private final String dataSealerInitParam = "dataSealerRef";

    /** init-param which can be passed to the servlet to specify the submodule list. */
    private final String submodulesInitParam = "submodules";

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter(submodulesInitParam) == null) {
            throw new ServletException("Required init-param (submodules) not set.");
        }
        submodules = getInitParameter(submodulesInitParam).split(" ");
        if (submodules.length == 0) {
            throw new ServletException("Required init-param (submodules) was empty.");
        }
        submoduleMap = new HashMap<String, StatelessLoginSubmodule>(submodules.length);
        for (String smname : submodules) {
            StatelessLoginSubmodule sm = (StatelessLoginSubmodule) getServletContext().getAttribute(smname);
            if (sm == null) {
                throw new ServletException("Submodule (" + smname + ") was not found in servlet context.");
            }
            submoduleMap.put(smname, sm);
        }

        if (getInitParameter(cookieNameInitParam) != null) {
            cookieName = getInitParameter(cookieNameInitParam);
        }

        if (getInitParameter(errorPageInitParam) != null) {
            errorPage = getInitParameter(errorPageInitParam);
        }
        
        if (getInitParameter(errorContextInitParam) != null) {
            errorContext = getInitParameter(errorContextInitParam);
        }
        
        if (getInitParameter(lifetimeInitParam) != null) {
            Duration xmlDuration = XMLHelper.getDataTypeFactory().newDuration(getInitParameter(lifetimeInitParam));
            lifetime = xmlDuration.getTimeInMillis(new Date());
        }

        if (getInitParameter(dataSealerInitParam) != null) {
            dataSealer = (DataSealer) getServletContext().getAttribute(getInitParameter(dataSealerInitParam));
        } else {
            dataSealer = (DataSealer) getServletContext().getAttribute("shibboleth.DataSealer");
        }
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        LoginContext loginContext = HttpServletHelper.getLoginContext(
                HttpServletHelper.getStorageService(getServletContext()), getServletContext(), request);
        if (loginContext == null) {
            ServletContext servletCtx = (errorContext == null) ? getServletContext()
                    : getServletContext().getContext(errorContext);
            servletCtx.getRequestDispatcher(errorPage).forward(request, response);
            return;
        }
        
        // Check for identity in cookie.
        log.debug("Checking for authentication state in SSO cookie.");
        StatelessAuthenticationInfo info = recoverFromCookie(request, response);
        boolean saveToCookie = true; // set to false to avoid rewrite of existing cookie
        
        // Check for "j_continue" to determine whether this is first time entry.
        // This is easily spoofable, but ForceAuthn is usually easy to get
        // around anyway.
        if (request.getParameter("j_continue") == null) {
            if (info != null) {
                if (!loginContext.isForceAuthRequired()) {
                    // No forced login, so see if we can satisfy the requester's needs.
                    List<String> requestedMethods = loginContext.getRequestedAuthenticationMethods();
                    if (requestedMethods == null || requestedMethods.isEmpty() ||
                            requestedMethods.contains(info.getAuthnMethod())) {
                        // Looks good, note that we don't need to save this back.
                        saveToCookie = false;
                    } else {
                        log.info("Requested authentication method not satisfied by previous login, bypassing SSO cookie.");
                        invalidateCookie(request, response);
                        info = null;
                    }
                } else {
                    log.info("Request is for forced authentication, bypassing SSO cookie.");
                    invalidateCookie(request, response);
                    info = null;
                }
            } else {
                // No valid identity yet. Check for passive requirement.
                if (loginContext.isPassiveAuthRequired()) {
                    log.warn("Request for passive authentication cannot be satisfied.");
                    request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY,
                            new PassiveAuthenticationException());
                    AuthenticationEngine.returnToAuthenticationEngine(request, response);
                }
            }
        } else if (info != null) {
            // In theory, this is a continuation from a warning message of some kind,
            // so we finish the login based on the previously established identity.
            completeLogin(request, response, info, false);
        }

        // If info remains valid, we're already authenticated.
        // Need to run submodules anyway, to support authz.
        if (info == null) {
            info = new StatelessAuthenticationInfo();
        }
        info.setLoginContext(loginContext);

        // Loop through the registered submodules until a response has been generated.
        for (String smname : submodules) {
            // Continue execution by next submodule.
            log.debug("Running login submodule {}", smname);
            StatelessLoginSubmodule sm = submoduleMap.get(smname);
            if (sm == null) {
                log.warn("Skipping unrecognized submodule {}", smname);
                continue;
            }

            try {
                sm.run(this, request, response, info);
                if (response.isCommitted()) {
                    // A response was generated.
                    return;
                }
            } catch (AuthenticationException e) {
                // Save off exception.
                log.error("Login submodule {} failed: {}", smname, e.getMessage());
                info.setAuthnException(e);
            } catch (LoginException e) {
            	// Save off login exception.
            	info.setLoginException(e);
            }
        }

        if (info.getAuthnException() == null && info.isAuthenticated()) {
            // Login completed with no fatal error,
            // so send back a Principal and save to cookie if needed.
            completeLogin(request, response, info, saveToCookie);
            return;
        }
        
        log.error("No response generated after running all submodules.");
        if (info.getAuthnException() != null) {
            request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, info.getAuthnException());
        } else if (info.getLoginException() != null) {
            request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, info.getLoginException());
        } else {
        	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY,
        			new AuthenticationException("Submodule configuration is invalid."));
        }
        AuthenticationEngine.returnToAuthenticationEngine(request, response);
    }

    /* Don't think we'll need this.
    private void continueLogin(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            StatelessAuthenticationInfo info, String continuation) {
        try {
            // Continue execution by a specific submodule.
            log.debug("Continuing dialog with user by submodule {}", continuation);
            StatelessLoginSubmodule sm = submoduleMap.get(continuation);
            if (sm == null) {
                log.error("Login continuation to an unrecognized submodule {}", continuation);
                throw new AuthenticationException("Login continuation to an unrecognized submodule.");
            }
            sm.run(this, httpRequest, httpResponse, info);
            if (info != null) {
                // Login completed, so send back a Principal and save to cookie.
                completeLogin(httpRequest, httpResponse, info, true);
            } else if (!httpResponse.isCommitted()) {
                throw new AuthenticationException("Login continuation left system in an ambiguous state.");
            }
        } catch (AuthenticationException e) {
            httpRequest.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, e);
            AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
        }
    }
    */

    private void completeLogin(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            StatelessAuthenticationInfo info, boolean saveToCookie) {
        log.debug("Using authenticated identity of {}", info.getUsername());
        if (saveToCookie) {
            try {
                saveToCookie(httpRequest, httpResponse, info);
            } catch (DataSealerException e) {
                log.error("Error while saving authentication info to cookie, SSO will not be possible: " + e);
            }
        }
        httpRequest.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, info.getUsername());
        httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, info.getAuthnMethod());
        httpRequest.setAttribute(LoginHandler.AUTHENTICATION_INSTANT_KEY, new DateTime(info.getAuthnInstant()));
        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }
    
    /**
     * Returns true iff the cookie address should be validated against the client.
     * 
     * @param addr	the cookie address
     * @return	indicator of whether to validate the address
     */
    private boolean checkAddress(String addr) {
    	// TODO: implement exclusions
    	return true;
    }
    
    /**
     * Recovers an existing session with a user from a cookie.
     * 
     * @param httpRequest   incoming request
     * @param httpResponse  outbound response
     * @return  an object containing the recovered identity or null
     */
    private StatelessAuthenticationInfo recoverFromCookie(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        Cookie cookie = HttpServletHelper.getCookie(httpRequest, cookieName);
        if (cookie != null && !"INVALID".equals(cookie.getValue())) {
            log.debug("Found SSO cookie ({}).", cookie.getValue());
            try {
                StatelessAuthenticationInfo info =
                    new StatelessAuthenticationInfo(dataSealer.unwrap(cookie.getValue()));
                log.debug("Recovered username ({}) from cookie.", info.getUsername());
                
                if (checkAddress(info.getAddress()) && !info.getAddress().equals(httpRequest.getRemoteAddr())) {
                	log.warn("Client address mismatch for username ({}): actual {}, cookie issued to {}",
                			new Object[] {info.getUsername(), httpRequest.getRemoteAddr(), info.getAddress() });
                	invalidateCookie(httpRequest, httpResponse);
                	return null;
                }
                
                return info;
            } catch (DataExpiredException e) {
                log.info("Recovered authentication info has expired.");
                invalidateCookie(httpRequest, httpResponse);
            } catch (DataSealerException e) {
                log.error("Error while recovering authentication info from cookie: " + e);
                invalidateCookie(httpRequest, httpResponse);
            }
        }
        return null;
    }

    /**
     * Invalidates the SSO cookie.
     * 
     * @param httpRequest   incoming request
     * @param httpResponse  outbound response
     */
    private void invalidateCookie(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        Cookie cookie = new Cookie(cookieName, "INVALID");
        cookie.setSecure(true);
        cookie.setPath(httpRequest.getContextPath() + httpRequest.getServletPath());
        httpResponse.addCookie(cookie);
    }
    
    /**
     * Stores the authenticated identity in a cookie.
     * 
     * @param httpRequest   incoming request
     * @param httpResponse  outbound response
     * @param info          object containing the identity
     * @throws DataSealerException
     */
    public void saveToCookie(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            StatelessAuthenticationInfo info) throws DataSealerException {
    	info.setAddress(httpRequest.getRemoteAddr());
        Cookie cookie = new Cookie(cookieName, dataSealer.wrap(info.getPickled(), info.getAuthnInstant()
                + lifetime));
        cookie.setSecure(true);
        cookie.setPath(httpRequest.getContextPath() + httpRequest.getServletPath());
        httpResponse.addCookie(cookie);
    }
 }
