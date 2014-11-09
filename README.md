Ohio State Shibboleth IdP Extensions
====================================

This extension module is available for use under the Apache 2.0 license,
and all the code is (c) The Ohio State University, written by Scott Cantor.

No support is available or implied by the availability of this code,
but questions, suggestions, or improvements may be discussed on
the dev@shibboleth.net mailing list, like any other community
contribution to the Shibboleth Project.

Much of the original extension work has been donated to the project
and can be found in the latest releases. What's left is primarily
a custom login handler that supports SSO in conjunction with stateless
clustering, as described in the Shibboleth Wiki.

The login handler is actually a framework for running an arbitrary
number of "submodules" that do actual work, such as displaying
a login form, checking passwords, and various other tasks.

To use the handler, the steps shown below need to be performed.
The details will vary widely based on your needs. If you don't
understand a change you're making, you need to go learn about
whatever piece of Java, Spring, etc. you're touching and figure
that out first. You can't literally cut and paste any of this,
it's not showing the surrounding context of each piece.

The example is one that allows for form-based authentication via a
Velocity template, with the back-end handled by Kerberos, SecurID,
and LDAP at the same time. The custom Spring config includes beans
for both the custom login extension and the now-built-in support
for transientID generation for stateless queries since they
usually get deployed together.

Some other things the code has some skeletal work done on include
resolving a subset of attributes during the login process, using
the data for things like authorization at the IdP or notifying
users their password will be expiring soon.

1. Install a custom servlet in web.xml and declare submodules to run.
---------------------------------------------------------------------
```xml
<!-- Add custom Spring config file to set -->
<context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>$IDP_HOME$/conf/internal.xml; $IDP_HOME$/conf/service.xml; $IDP_HOME$/conf/osuext.xml</param-value>
</context-param>


<!-- Servlet for doing stateless cookie-based authentication -->
<servlet>
    <servlet-name>StatelessAuthHandler</servlet-name>
    <servlet-class>edu.osu.ocio.shibboleth.idp.authn.provider.StatelessLoginServlet</servlet-class>
    <load-on-startup>5</load-on-startup>
    <init-param>
        <param-name>dataSealerRef</param-name>
        <param-value>shibboleth.SSODataSealer</param-value>
    </init-param>
    <init-param>
        <param-name>submodules</param-name>
        <param-value>shibboleth.KerberosLoginSubmodule shibboleth.SecurIDLoginSubmodule shibboleth.LDAPLoginSubmodule shibboleth.VelocityFormLoginSubmodule</param-value>
    </init-param>
    <init-param>
        <param-name>errorContext</param-name>
        <param-value>/</param-value>
    </init-param>
    <init-param>
        <param-name>errorPage</param-name>
        <param-value>/stale.html</param-value>
    </init-param>
</servlet>

<servlet-mapping>
    <servlet-name>StatelessAuthHandler</servlet-name>
    <url-pattern>/Authn/Stateless</url-pattern>
</servlet-mapping>
```

2. Modify handler.xml to use the extension namespace and custom login module.
-----------------------------------------------------------------------------
```xml
<ProfileHandlerGroup xmlns="urn:mace:shibboleth:2.0:idp:profile-handler"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xmlns:osu="urn:mace:osu.edu:shibboleth:idp-ext"
                     xsi:schemaLocation="urn:mace:shibboleth:2.0:idp:profile-handler classpath:/schema/shibboleth-2.0-idp-profile-handler.xsd
                                         urn:mace:osu.edu:shibboleth:idp-ext classpath:/schema/idp-osu-ext.xsd">


<LoginHandler xsi:type="osu:Stateless" authenticationServletURL="/Authn/Stateless">
    <AuthenticationMethod>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthenticationMethod>
    <AuthenticationMethod>urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</AuthenticationMethod>
</LoginHandler>
```

3. Declare beans in custom Spring extension file added to web.xml.
------------------------------------------------------------------
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:util="http://www.springframework.org/schema/util"
     xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-2.0.xsd
                         http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util-2.0.xsd" >

    <bean id="shibboleth.TransientIDDataSealer" class="edu.internet2.middleware.shibboleth.common.util.DataSealer" 
          depends-on="shibboleth.LogbackLogging" init-method="init">
        <property name="keystorePath" value="/opt/shibboleth-idp/credentials/secret.jks" />
        <property name="keystorePassword" value="foo" />
        <property name="cipherKeyAlias" value="nameid" />
	<property name="cipherKeyPassword" value="foo" />
    </bean>

    <bean id="shibboleth.SSODataSealer" class="edu.internet2.middleware.shibboleth.common.util.DataSealer"
          depends-on="shibboleth.LogbackLogging" init-method="init">
        <property name="keystorePath" value="/opt/shibboleth-idp/credentials/secret.jks" />
        <property name="keystorePassword" value="foo" />
        <property name="cipherKeyAlias" value="sso" />
        <property name="cipherKeyPassword" value="foo" />
    </bean>

    <bean id="shibboleth.SSOVelocityEngine" class="org.springframework.ui.velocity.VelocityEngineFactoryBean" depends-on="shibboleth.LogbackLogging">
        <property name="overrideLogging" value="false"/>
        <property name="velocityProperties">
            <props>
                <prop key="runtime.log.logsystem.class">
                    edu.internet2.middleware.shibboleth.common.util.Slf4JLogChute
                </prop>
                <prop key="resource.loader">file</prop>
                <prop key="file.resource.loader.class">
                    org.apache.velocity.runtime.resource.loader.FileResourceLoader
                </prop>
                <prop key="file.resource.loader.path">/opt/shibboleth-idp/conf</prop>
                <prop key="file.resource.loader.cache">false</prop>
            </props>
        </property>
    </bean>

    <bean id="shibboleth.KerberosLoginSubmodule" class="edu.osu.ocio.shibboleth.idp.authn.provider.JAASLoginSubmodule">
        <constructor-arg value="file:///opt/jetty/etc/jaas.conf" />
        <property name="jaasConfigName" value="ShibKerberosAuth" />
        <property name="authnMethods">
          <set>
            <value>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</value>
          </set>
        </property>
        <property name="unknownUsernameErrors">
          <list>
            <value>CLIENT_NOT_FOUND</value>
            <value>Cannot get kdc for realm</value>
          </list>
        </property>
        <property name="invalidPasswordErrors">
          <list>
            <value>Integrity check on decrypted field failed</value>
          </list>
        </property>
    </bean>

    <bean id="shibboleth.SecurIDLoginSubmodule" class="edu.osu.ocio.shibboleth.idp.authn.provider.JAASLoginSubmodule">
        <constructor-arg value="file:///opt/jetty/etc/jaas.conf" />
        <property name="jaasConfigName" value="ShibSecurIDAuth" />
        <property name="authnMethods">
          <set>
            <value>urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</value>
          </set>
        </property>
        <property name="invalidPasswordErrors">
          <list>
            <value>SecurID authentication failed with status</value>
          </list>
        </property>
    </bean>

    <bean id="shibboleth.LDAPLoginSubmodule" class="edu.osu.ocio.shibboleth.idp.authn.provider.JAASLoginSubmodule">
        <constructor-arg value="file:///opt/jetty/etc/jaas.conf"/>
        <property name="jaasConfigName" value="ShibLDAPAuth" />
        <property name="authnMethods">
          <set>
            <value>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</value>
          </set>
        </property>
        <property name="unknownUsernameErrors">
          <list>
            <value>Cannot authenticate dn, invalid dn</value>
          </list>
        </property>
        <property name="invalidPasswordErrors">
          <list>
            <value>AcceptSecurityContext error, data 52e</value>
          </list>
        </property>
    </bean>

    <bean id="shibboleth.VelocityFormLoginSubmodule" class="edu.osu.ocio.shibboleth.idp.authn.provider.VelocityFormLoginSubmodule"
            depends-on="shibboleth.LogbackLogging">
        <property name="templateName" value="login.vt" />
        <property name="velocityEngine" ref="shibboleth.SSOVelocityEngine" />
    </bean>

    <bean id="shibboleth.OSUServletAttributeExporter"
          class="edu.internet2.middleware.shibboleth.common.config.service.ServletContextAttributeExporter" 
          depends-on="shibboleth.LogbackLogging shibboleth.SSODataSealer shibboleth.KerberosLoginSubmodule shibboleth.SecurIDLoginSubmodule shibboleth.LDAPLoginSubmodule shibboleth.VelocityFormLoginSubmodule"
         init-method="initialize" >
        <constructor-arg>
           <list>
               <value>shibboleth.SSODataSealer</value>
               <value>shibboleth.KerberosLoginSubmodule</value>
               <value>shibboleth.SecurIDLoginSubmodule</value>
               <value>shibboleth.LDAPLoginSubmodule</value>
               <value>shibboleth.VelocityFormLoginSubmodule</value>
           </list>
        </constructor-arg>
    </bean>

</beans>
```

4. Create a login.vt template in $IDP_HOME/conf.
------------------------------------------------
```html
<!-- excerpt of the interesting bits -->

<div id="loginForm">

#if ($authnInfo.isAccountLocked())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">Login failed. Your Ohio State Username account is locked.</p>
    </blockquote>
#elseif ($authnInfo.isExpiredPassword())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">Login failed. The password associated with your Ohio State Username account has expired.</p>
    </blockquote>
#elseif ($authnInfo.isInvalidPassword())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">Login failed. The password you entered is incorrect.</p>
    </blockquote>
#elseif ($authnInfo.isUnknownUsername())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">Login failed. The username you entered cannot be identified.</p>
    </blockquote>
#elseif ($authnInfo.getLoginException())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">An error occurred during login: $encoder.encode($authnInfo.getLoginException().getMessage())</p>
    </blockquote>
#elseif ($authnInfo.getAuthnException())
    <blockquote style="font-weight:bold; text-align:left">
    <p style="color:#cc0000">An error occurred during login: $encoder.encode($authnInfo.getAuthnException().getMessage())</p>
    </blockquote>
#end
    <form name="login" method="POST" action="$servletPath">
        <fieldset>
            <legend>Identify Yourself</legend>
            <div>
                <label for="userid">
                    Enter your Username
                </label>
                <br/>
                <input type="text" class="text" id="userid" name="j_username" size="50"/>
            </div>
        </fieldset>
        <fieldset>
            <legend>Password <span class="smallOr">or</span> Passcode</legend>
            <div>
                <label for="password">
                    Enter your account password.<br/>
                </label>
                <br/>
                <input type="password" class="text" id="password"  name="j_password" size="50"/>
            </div>
        </fieldset>
        <input type="hidden" name="j_continue" value="1"/>
        <input id="submit" class="submit" type="submit" value="Login"/>
    </form>
    
</div>
```
