package com.hma.idpbrokerservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan(basePackages = "com.hma.idpbrokerservice")
public class IamBrokerApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamBrokerApplication.class, args);
    }
}
