package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.security.AuthInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** 注册鉴权拦截器；两步登录与刷新端点公开，其余控制器入口默认纳入。 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    public WebMvcConfig(AuthInterceptor authInterceptor) {
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(
                        "/api/auth/login/password",
                        "/api/auth/login/otp",
                        "/api/auth/refresh"
                );
    }
}
