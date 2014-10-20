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

import java.io.PrintWriter;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import edu.internet2.middleware.shibboleth.common.util.DataSealerException;

/**
 * Submodule that produces password expiration warnings, and
 * possibly other messaging in the future.
 */
public class NotificationLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(NotificationLoginSubmodule.class);

    /** Velocity engine to use to render notification. */
    private VelocityEngine velocity;

    /** Name of notification template. */
    private String templateName;
    
    /** Name of password expiration attribute. */
    private String passwordExpiration = "passwordExpiration";
    
    /** Notification window in ms. */
    private int notifyWindow = 1000 * 3600 * 24 * 14;

    /** Notification interval in ms. */
    private int notifyInterval = 1000 * 3600 * 8;
    
    /** Name of cookie to track prior notifications. */
    private String notifyCookie = "_osu_idp_notify";

    /** Consume timestamp as an Active Directory COBOL clusterfuck. */
    private boolean activeDirectoryConversion = false;
    
    /**
     * Gets the template engine.
     * @return the template engine
     */
    public VelocityEngine getVelocityEngine() {
        return velocity;
    }

    /**
     * Gets the template name.
     * @return the templateName
     */
    public String getTemplateName() {
        return templateName;
    }

    /**
     * Gets the name of the password expiration attribute.
     * @return the password expiration attribute name
     */
    public String getPasswordExpiration() {
        return passwordExpiration;
    }

    /**
     * Gets the time in ms before a password expires to start notifying.
     * @return time in ms before a password expires to start notifying
     */
    public int getNotifyWindow() {
        return notifyWindow;
    }

    /**
     * Gets the time in ms between notifications.
     * @return time in ms between notifications
     */
    public int getNotifyInterval() {
        return notifyInterval;
    }

    /**
     * Gets the name of the cookie to record the last notification.
     * @return name of the cookie to record the last notification
     */
    public String getNotifyCookie() {
        return notifyCookie;
    }

    /**
     * Gets the AD conversation setting
     * @return	true iff the password expiration is in AD format
     */
    boolean getActiveDirectoryConversion() {
    	return activeDirectoryConversion;
    }
    
    /**
     * Sets the template engine.
     * @param v the template engine to set
     */
    public void setVelocityEngine(VelocityEngine v) {
        velocity = v;
    }

    /**
     * Sets the template name.
     * @param t the templateName to set
     */
    public void setTemplateName(String t) {
        templateName = t;
    }

    /**
     * Sets the name of the password expiration attribute.
     * @param exp the password expiration attribute name
     */
    public void setPasswordExpiration(String exp) {
        passwordExpiration = exp;
    }

    /**
     * Sets the time in ms before a password expires to start notifying.
     * @param secs time in ms
     */
    public void setNotifyWindow(int ms) {
        notifyWindow = ms;
    }

    /**
     * Sets the time in ms between notifications.
     * @param secs time in ms
     */
    public void setNotifyInterval(int ms) {
        notifyInterval = ms;
    }

    /**
     * Sets the name of the cookie to record the last notification.
     * @param name name of the cookie
     */
    public void setNotifyCookie(String name) {
        notifyCookie = name;
    }
    
    /**
     * Sets the AD conversion flag.
     * 
     * @param b true iff the password expiration is in AD format
     */
    public void setActiveDirectoryConversion(boolean b) {
    	activeDirectoryConversion = b;
    }
    
    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response, StatelessAuthenticationInfo info) throws AuthenticationException {

        if (!info.isAuthenticated() || request.getParameter("j_notify") != null) {
            return;
        }
       
        Cookie cookie = HttpServletHelper.getCookie(request, notifyCookie);
        
        Map<String,String> attrs = info.getResolvedAttributes();
        String exp = (attrs != null) ? attrs.get(passwordExpiration) : null;
        if (exp != null) {
        	long now = System.currentTimeMillis();
        	long timeLeft = activeDirectoryConversion ? convertFromAD(exp) : Long.parseLong(exp);         	
        	if (log.isDebugEnabled()) {
        		log.debug("password for {} expires at {}",
        				info.getUsername(), new DateTime(timeLeft, DateTimeZone.getDefault()));
        	}

        	timeLeft -= now;
            if (timeLeft < 0) {
                log.warn("Password apparently expired, should have been reported as a login error");
            } else if (timeLeft > getNotifyWindow()) {
                if (cookie != null) {
                    log.debug("Password expiration not imminent, clearing cookie");
                    cookie.setValue("");
                    cookie.setMaxAge(0);
                    cookie.setSecure(true);
                    cookie.setPath(request.getContextPath() + request.getServletPath());
                    response.addCookie(cookie);
                }
            } else {
                long lastNotify = (cookie != null) ? Long.parseLong(cookie.getValue()) : 0;
                if (now - lastNotify > getNotifyInterval()) {
                    log.debug("Triggering password expiration warning, saving login identity to SSO cookie");
                    try {
                        servlet.saveToCookie(request, response, info);
                    } catch (DataSealerException e) {
                        log.error("Skipping notification due to error preserving login identity: {}", e.getMessage());
                        return;
                    }
                    if (cookie == null) {
                        cookie = new Cookie(notifyCookie, Long.toString(now));
                    } else {
                        cookie.setValue(Long.toString(now));
                    }
                    cookie.setMaxAge(getNotifyWindow() / 1000);
                    cookie.setSecure(true);
                    cookie.setPath(request.getContextPath() + request.getServletPath());
                    response.addCookie(cookie);
                    response.setContentType("text/html");
                    response.setHeader("Cache-Control", "content=\"no-store,no-cache,must-revalidate\"");
                    response.setHeader("Pragma","no-cache");
                    response.setHeader("Expires","-1");
                    
                    VelocityContext vCtx = new VelocityContext();
                    vCtx.put("authnInfo", info);
                    vCtx.put("servletPath", request.getContextPath() + request.getServletPath());
                    vCtx.put("passwordExpiration",
                            DateTimeFormat.forPattern("EEEE MMMM d, h:mm a").print(now + timeLeft));
                    
                    try {
                        Template template = velocity.getTemplate(templateName);
                        PrintWriter writer = response.getWriter();
                        template.merge(vCtx, writer);
                        writer.flush();
                    } catch (Exception e) {
                        log.error(e.getMessage());
                        throw new AuthenticationException("Error while processing notification template.", e);
                    }
                }
            }
        }
    }

    private long convertFromAD(String s) {
    	long result = Long.parseLong(s);

    	// Filetime Epoch is JAN 01 1601
    	// java date Epoch is January 1, 1970

    	// so take the number and subtract java Epoch:
    	result -= 0x19db1ded53e8000L;

    	// convert UNITS from (100 nano-seconds) to (milliseconds)
    	result /= 10000;
    	
    	return result;
    }
}
