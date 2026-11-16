package com.secretdrop.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI secretDropOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("SecretDrop API")
                        .description("Self-destructing encrypted secret sharing service")
                        .version("1.0.0")
                        .contact(new Contact().name("SecretDrop")));
    }
}