package com.trendprice.securitysite.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME_NAME = "bearerAuth";

    @Bean
    public OpenAPI securitySiteOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Security Site API")
                        .description("""
                                Backend API for registration, authentication, email verification,
                                password reset, JWT access token, refresh token, logout,
                                user profile and admin user management.
                                """)
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Aruzhan Mukhametzhanova")
                                .email("aruzanmuhametzanova@gmail.com"))
                        .license(new License()
                                .name("Diploma Project")))
                .addSecurityItem(new SecurityRequirement()
                        .addList(SECURITY_SCHEME_NAME))
                .components(new Components()
                        .addSecuritySchemes(
                                SECURITY_SCHEME_NAME,
                                new SecurityScheme()
                                        .name(SECURITY_SCHEME_NAME)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                        ));
    }
}