package com.rivers.oauth2.oath.adaper;

import com.rivers.oauth2.config.FilterIgnorePropertiesConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * @author riversking
 */
public abstract class BaseResourceServerConfigurerAdapter extends ResourceServerConfigurerAdapter {

    @Autowired
    private FilterIgnorePropertiesConfig filterIgnorePropertiesConfig;

    /**
     * 默认的配置，对外暴露
     *
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception{
        //允许使用iframe 嵌套，避免swagger-ui 不被加载的问题
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>
                .ExpressionInterceptUrlRegistry registry = http
                .authorizeRequests();
        filterIgnorePropertiesConfig.getUrls()
                .forEach(url -> registry.antMatchers(url).permitAll());
        registry.antMatchers("/actuator/**").permitAll().anyRequest().authenticated()
                .and().csrf().disable();
    }

}
