/*
 * Copyright 2012 The Ohio State University
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

package edu.osu.ocio.shibboleth.common.attribute.resolver.provider.dataConnector;

import javax.xml.namespace.QName;
import org.w3c.dom.Element;
import edu.osu.ocio.shibboleth.config.NamespaceHandler;

/**
 * Parses configuration of our customized LDAP connector.
 * 
 * @author Scott Cantor
 *
 */
public class LdapDataConnectorBeanDefinitionParser
		extends
		edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.LdapDataConnectorBeanDefinitionParser {

    /** Custom LDAP data connector type name. */
    public static final QName TYPE_NAME = new QName(NamespaceHandler.NAMESPACE, "GracefulPoolLDAPDirectory");
	
    /** {@inheritDoc} */
    protected Class<?> getBeanClass(Element element) {
        return LdapDataConnectorFactoryBean.class;
    }
	
}
