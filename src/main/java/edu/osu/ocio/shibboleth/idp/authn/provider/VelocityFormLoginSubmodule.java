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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.owasp.esapi.ESAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;

/**
 * Submodule that produces a login form using a Velocity template.
 */
public class VelocityFormLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(VelocityFormLoginSubmodule.class);

    /** Velocity engine to use to render login form. */
    private VelocityEngine velocity;

    /** Name of login form template. */
    private String templateName;
    
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
   
    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response, StatelessAuthenticationInfo info) throws AuthenticationException {
        
        if (info.isAuthenticated()) {
            return;
        }
        
        VelocityContext vCtx = new VelocityContext();
        vCtx.put("username", request.getParameter("j_username"));
        vCtx.put("authnInfo", info);
        vCtx.put("servletPath", request.getContextPath() + request.getServletPath());
        vCtx.put("encoder", ESAPI.encoder());

        response.setContentType("text/html");
        response.setHeader("Cache-Control", "content=\"no-store,no-cache,must-revalidate\"");
        response.setHeader("Pragma","no-cache");
        response.setHeader("Expires","-1");
        
        try {
            Template template = velocity.getTemplate(templateName);
            PrintWriter writer = response.getWriter();
            template.merge(vCtx, writer);
            writer.flush();
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new AuthenticationException("Error while processing login template.", e);
        }
    }

}
