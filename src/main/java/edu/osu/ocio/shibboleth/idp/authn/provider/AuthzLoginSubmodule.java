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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Submodule that checks for a permission attribute before allowing access.
 */
public class AuthzLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AuthzLoginSubmodule.class);

    /** Velocity engine to use to render error. */
    private VelocityEngine velocity;

    /** Name of error template. */
    private String templateName;
    
    /** Name of permission attribute. */
    private String permissionName;

    /** Names of SPs to manage access for. */
    private Set<String> relyingParties = new HashSet<String>();
    
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
     * Gets the name of the permission attribute.
     * @return the permission attribute name
     */
    public String getPermissionName() {
        return permissionName;
    }

    /**
     * Gets the SPs to manage access for.
     * @return	list of SPs to manage
     */
    public Set<String> getRelyingParties() {
		return relyingParties;
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
     * Sets the name of the permission attribute.
     * @param permissionName the permission attribute name
     */
    public void setPermissionName(String permissionName) {
        this.permissionName = permissionName;
    }

    /**
     * Sets the SPs to manage access for
     * @param relyingParties SPs to manage
     */
	public void setRelyingParties(Set<String> relyingParties) {
		this.relyingParties = relyingParties;
	}
    
    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response, StatelessAuthenticationInfo info) throws AuthenticationException {

        if (!info.isAuthenticated() || request.getParameter("j_notify") != null) {
            return;
        }
        
        // Check to see if we're managing this SP.
        String rpID = info.getLoginContext().getRelyingPartyId();
        if (!relyingParties.isEmpty()) {
	        if (rpID == null || !relyingParties.contains(rpID)) {
	        	return;
	        }
        }
        
        log.debug("Monitoring access to relying party {}", rpID);
       
        Map<String,String> attrs = info.getResolvedAttributes();
        String perm = (attrs != null) ? attrs.get(permissionName) : null;
        if (perm != null && "1".equals(perm)) {
        	return;
        }
        
        log.warn("Access denied for relying party {} to principal {}", rpID, info.getUsername());
        
        response.setContentType("text/html");
        response.setHeader("Cache-Control", "content=\"no-store,no-cache,must-revalidate\"");
        response.setHeader("Pragma","no-cache");
        response.setHeader("Expires","-1");

        VelocityContext vCtx = new VelocityContext();
        vCtx.put("authnInfo", info);
        vCtx.put("servletPath", request.getContextPath() + request.getServletPath());
        try {
            Template template = velocity.getTemplate(templateName);
            HttpServletHelper.unbindLoginContext(HttpServletHelper.getStorageService(servlet.getServletContext()),
            		servlet.getServletContext(), request, response);
            PrintWriter writer = response.getWriter();
            template.merge(vCtx, writer);
            writer.flush();
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new AuthenticationException("Error while processing notification template.", e);
        }
    }

}
