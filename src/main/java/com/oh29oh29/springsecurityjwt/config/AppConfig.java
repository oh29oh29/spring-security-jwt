package com.oh29oh29.springsecurityjwt.config;

import com.google.gson.Gson;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan("com.oh29oh29.**")
public class AppConfig {

    @Bean
    public Gson gson() {
        return new Gson();
    }
}
