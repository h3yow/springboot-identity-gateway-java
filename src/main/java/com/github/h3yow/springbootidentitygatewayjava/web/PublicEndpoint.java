package com.github.h3yow.springbootidentitygatewayjava.web;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注无需访问令牌即可调用的公开端点（登录、刷新、撤销）。
 * 这是拦截器中唯一的显式放行通道，未标注的 /api 入口一律默认拒绝。
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PublicEndpoint {
}
