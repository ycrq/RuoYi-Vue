package com.ruoyi.mailConfig;

import com.ruoyi.framework.smsConfig.SmsCodeAuthenticationProvider;
import com.ruoyi.framework.web.service.MailUserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class MailCodeAuthenticationSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    MailUserDetailsServiceImpl userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {

        MailCodeAuthenticationProvider mailCodeAuthenticationProvider = new  MailCodeAuthenticationProvider();
        mailCodeAuthenticationProvider.setUserDetailsService(userDetailsService);

        http.authenticationProvider(mailCodeAuthenticationProvider);

    }

}
