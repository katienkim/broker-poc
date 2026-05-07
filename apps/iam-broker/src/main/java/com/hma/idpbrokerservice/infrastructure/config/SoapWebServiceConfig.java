package com.hma.idpbrokerservice.infrastructure.config;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.SimpleWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the Spring-WS dispatcher and publishes one WSDL per SOAP service.
 * Each WSDL becomes available at /ws/{name}.wsdl; the SOAP endpoint
 * itself routes by `@PayloadRoot` namespace+localPart.
 *
 * Path layout (matches client `<soap:address location="/ws"/>`):
 *   /ws                          — single SOAP receive endpoint
 *   /ws/publishtoken.wsdl        — token mint contract
 *   /ws/authenticateuser.wsdl    — vendor-side validation contract
 *   /ws/otpvalidate.wsdl         — WPC OTP contract
 *   /ws/adminrevoke.wsdl         — admin revoke contract
 *   /ws/adminbypass.wsdl         — admin bypass contract
 */
@EnableWs
@Configuration
public class SoapWebServiceConfig extends WsConfigurerAdapter {

    @Bean
    public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(ApplicationContext ctx) {
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(ctx);
        servlet.setTransformWsdlLocations(true);
        return new ServletRegistrationBean<>(servlet, "/ws/*");
    }

    @Bean(name = "publishtoken")
    public SimpleWsdl11Definition publishtokenWsdl() {
        return new SimpleWsdl11Definition(new ClassPathResource("wsdl/publishtoken.wsdl"));
    }

    @Bean(name = "authenticateuser")
    public SimpleWsdl11Definition authenticateuserWsdl() {
        return new SimpleWsdl11Definition(new ClassPathResource("wsdl/authenticateuser.wsdl"));
    }

    @Bean(name = "otpvalidate")
    public SimpleWsdl11Definition otpvalidateWsdl() {
        return new SimpleWsdl11Definition(new ClassPathResource("wsdl/otpvalidate.wsdl"));
    }

    @Bean(name = "adminrevoke")
    public SimpleWsdl11Definition adminrevokeWsdl() {
        return new SimpleWsdl11Definition(new ClassPathResource("wsdl/adminrevoke.wsdl"));
    }

    @Bean(name = "adminbypass")
    public SimpleWsdl11Definition adminbypassWsdl() {
        return new SimpleWsdl11Definition(new ClassPathResource("wsdl/adminbypass.wsdl"));
    }

    @Bean
    public XsdSchema publishtokenSchema() { return new SimpleXsdSchema(new ClassPathResource("xsd/publishtoken.xsd")); }

    @Bean
    public XsdSchema authenticateuserSchema() { return new SimpleXsdSchema(new ClassPathResource("xsd/authenticateuser.xsd")); }

    @Bean
    public XsdSchema otpvalidateSchema() { return new SimpleXsdSchema(new ClassPathResource("xsd/otpvalidate.xsd")); }

    @Bean
    public XsdSchema adminrevokeSchema() { return new SimpleXsdSchema(new ClassPathResource("xsd/adminrevoke.xsd")); }

    @Bean
    public XsdSchema adminbypassSchema() { return new SimpleXsdSchema(new ClassPathResource("xsd/adminbypass.xsd")); }
}
