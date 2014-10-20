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

package edu.osu.ocio.shibboleth.config;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;
import edu.osu.ocio.shibboleth.common.attribute.resolver.provider.dataConnector.LdapDataConnectorBeanDefinitionParser;
import edu.osu.ocio.shibboleth.idp.authn.provider.StatelessLoginHandlerBeanDefinitionParser;

/**
 * Spring namespace handler for the OSU Shibboleth extension namespace.
 */
public class NamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace for this handler. */
    public static final String NAMESPACE = "urn:mace:osu.edu:shibboleth:idp-ext";

    /** {@inheritDoc} */
    public void init() {
        registerBeanDefinitionParser(StatelessLoginHandlerBeanDefinitionParser.TYPE_NAME,
                new StatelessLoginHandlerBeanDefinitionParser());
        
        // Should override built-in bean parser so we can plugin our own bean factory.
        registerBeanDefinitionParser(LdapDataConnectorBeanDefinitionParser.TYPE_NAME,
                new LdapDataConnectorBeanDefinitionParser());
    }
}
