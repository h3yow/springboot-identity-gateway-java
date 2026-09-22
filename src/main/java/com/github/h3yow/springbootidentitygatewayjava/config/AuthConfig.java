package com.github.h3yow.springbootidentitygatewayjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** 启用 auth.* 配置属性绑定。 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthConfig {
}
