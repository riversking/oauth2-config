package com.rivers.oauth2.annotation;

import java.lang.annotation.*;

/**
 * @author riversking
 * <p>
 * 服务调用不鉴权注解
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Inner {

    /**
     * 是否AOP统一处理
     *
     * @return false, true
     */
    boolean value() default true;

    /**
     * 需要特殊判空的字段(预留)
     *
     * @return {}
     */
    String[] field() default {};

}
