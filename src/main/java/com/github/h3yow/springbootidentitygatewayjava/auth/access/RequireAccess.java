package com.github.h3yow.springbootidentitygatewayjava.auth.access;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注受保护入口所需的角色/权限/范围；任意一项满足即放行，全部按“至少一个”语义判定。
 * 默认值为空表示“仅要求已认证”。未标注的入口由拦截器默认拒绝。
 */
@Target({ElementType.METHOD, ElementType.TYPE, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireAccess {

    /** 要求的角色之一。 */
    String[] roles() default {};

    /** 要求的权限之一。 */
    String[] permissions() default {};

    /** 要求的令牌范围之一。 */
    String[] scopes() default {};
}
