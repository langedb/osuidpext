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

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;
import edu.osu.ocio.shibboleth.config.NamespaceHandler;

/**
 * Spring bean definition parser for stateless login handlers.
 */
public class StatelessLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName TYPE_NAME = new QName(NamespaceHandler.NAMESPACE, "Stateless");

    /** {@inheritDoc} */
    protected Class<StatelessLoginHandlerFactoryBean> getBeanClass(Element element) {
        return StatelessLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "authenticationServletURL")) {
            builder.addPropertyValue("authenticationServletURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,
                    "authenticationServletURL")));
        } else {
            builder.addPropertyValue("authenticationServletURL", "/Authn/Stateless");
        }
    }
}