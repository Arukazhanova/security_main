package com.trendprice.securitysite;

import com.trendprice.securitysite.config.AdminProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AdminProperties.class)
public class SecuritysiteApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuritysiteApplication.class, args);
	}
}