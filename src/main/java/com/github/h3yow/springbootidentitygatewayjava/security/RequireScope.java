package com.github.h3yow.springbootidentitygatewayjava.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注受保护入口所需的权限范围与允许角色。
 * 角色与范围均为“满足任一”（OR）；两类条件同时存在时取交集（先角色后范围）。
 * 未标注的控制器方法不纳入网关保护范围。
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScope {

    /** 需要的权限范围，满足其一即可；为空表示不检查范围。 */
    String[] value() default {};

    /** 允许的角色，满足其一即可；为空表示不检查角色。 */
    String[] roles() default {};
}
