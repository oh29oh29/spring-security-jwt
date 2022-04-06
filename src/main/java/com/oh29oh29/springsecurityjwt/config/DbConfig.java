package com.oh29oh29.springsecurityjwt.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories("com.oh29oh29.springsecurityjwt.**")
@EntityScan("com.oh29oh29.springsecurityjwt.**")
public class DbConfig {
}
