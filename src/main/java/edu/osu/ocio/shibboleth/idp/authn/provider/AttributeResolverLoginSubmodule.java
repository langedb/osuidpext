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
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.SAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Submodule that resolves attributes for a principal.
 */
public class AttributeResolverLoginSubmodule implements StatelessLoginSubmodule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AttributeResolverLoginSubmodule.class);

    /** Names of user attributes to resolve and manage. */
    private List<String> attributeNames;

    /** {@inheritDoc} */
    public void run(StatelessLoginServlet servlet, HttpServletRequest request, HttpServletResponse response,
            StatelessAuthenticationInfo info) throws AuthenticationException {

        // We have to know the username.
        if (info.getUsername() == null) {
            log.debug("Username not set, submodule returning");
            return;
        }

        // Recover data from form if the username matches.
        // This isn't secure, but the data we're using isn't
        // sensitive to user tampering unless they want to
        // bypass warnings and such.
        String resolved = request.getParameter("j_resolved");
        if (resolved != null && resolved.equals(info.getUsername())) {
            log.debug("Recovering page-cached attributes for {}", resolved);
            Map<String, String> attributeMap = info.getResolvedAttributes();
            for (String aname : attributeNames) {
                String aval = request.getParameter(aname);
                if (aval != null) {
                    attributeMap.put(aname, aval);
                }
            }
            return;
        }

        log.debug("Performing attribute resolution for {}", info.getUsername());

        AttributeResolver resolver = HttpServletHelper.getAttributeResolver(servlet.getServletContext());
        if (resolver != null) {
            try {
                Map<String, BaseAttribute> attrs = resolver.resolveAttributes(createRequestContext(
                        servlet.getServletContext(), request, info));
                Map<String, String> attributeMap = info.getResolvedAttributes();
                for (String aname : attributeNames) {
                    BaseAttribute attr = attrs.get(aname);
                    if (attr != null && !attr.getValues().isEmpty()) {
                        attributeMap.put(aname, attr.getValues().iterator().next().toString());
                    }
                }
            } catch (AttributeResolutionException e) {
                log.error("Failed to resolve attributes for {}: {}", info.getUsername(), e.getMessage());
            }
        } else {
            log.warn("No AttributeResolver instance available");
        }

        return;
    }

    /**
     * Gets the attribute names to resolve.
     * @return the attribute names to resolve
     */
    public List<String> getAttributeNames() {
        return attributeNames;
    }

    /**
     * Sets the attribute names to resolve
     * @param attributeNames the attribute names to resolve
     */
    public void setAttributeNames(List<String> attributeNames) {
        this.attributeNames = attributeNames;
    }
    
    private BaseSAMLProfileRequestContext<?, ?, ?, ?> createRequestContext(ServletContext context,
            HttpServletRequest request, StatelessAuthenticationInfo info) {
        BaseSAMLProfileRequestContext<?, ?, ?, ?> requestContext =
            new BaseSAMLProfileRequestContext<SAMLObject, SAMLObject, SAMLObject, ProfileConfiguration>();
        RelyingPartyConfiguration relyingPartyConfiguration =
            HttpServletHelper.getRelyingPartyConfigurationManager(context).getRelyingPartyConfiguration(
                    info.getLoginContext().getRelyingPartyId());
        String idpId = relyingPartyConfiguration.getProviderId();

        requestContext.setRelyingPartyConfiguration(relyingPartyConfiguration);
        requestContext.setInboundMessageIssuer(info.getLoginContext().getRelyingPartyId());
        requestContext.setOutboundMessageIssuer(idpId);
        requestContext.setPrincipalName(info.getUsername());
        requestContext.setLocalEntityId(idpId);
        requestContext.setPeerEntityId(info.getLoginContext().getRelyingPartyId());
        requestContext.setRequestedAttributes(attributeNames);

        return requestContext;
    }
}
