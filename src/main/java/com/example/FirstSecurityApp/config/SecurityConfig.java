package com.example.FirstSecurityApp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
@Bean
public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/admin").hasRole("ADMIN")
                    .requestMatchers("/auth/login", "/auth/registration","/error").permitAll()
                    .anyRequest().hasAnyRole("USER","ADMIN")
            )
            .formLogin(form -> form
                    .loginPage("/auth/login")
                    .permitAll()
            )
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/hello")
                    .invalidateHttpSession(true)
            );

    return httpSecurity.build();
}

//    @Bean   //    ******************** Custom login form
//    public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.csrf().and().cors().disable()
//                .authorizeHttpRequests()
//                .requestMatchers("/auth/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin(form -> form
//                        .loginPage("/auth/login")
//                        .permitAll()
//                );
//        return httpSecurity.build();
//    }

    // **************************** Стандартная форма
//    @Bean
//    public SecurityFilterChain configure(final HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity.csrf().and().cors().disable()
//                .authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().defaultSuccessUrl("/hello", true)
//                .and().build();
//    }

}


    //    *******************  Если используем старый способ с WebSecurityConfigurerAdapter
//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//    private final PersonDetailsService personDetailsService;
//    @Autowired
//    public SecurityConfig(PersonDetailsService personDetailsService) {
//        this.personDetailsService = personDetailsService;
//    }
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(personDetailsService);
//    }
//    @Bean
//    public PasswordEncoder getPasswordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            // конфигурируем сам Spring Security
//            // конфигурируем авторизацию
//            http.authorizeRequests()
//                    .antMatchers("/admin").hasRole("ADMIN")
//                    .antMatchers("/auth/login", "/auth/registration", "/error").permitAll()
//                    .anyRequest().hasAnyRole("USER", "ADMIN")
//                    .and()
//                    .formLogin().loginPage("/auth/login")
//                    .loginProcessingUrl("/process_login")
//                    .defaultSuccessUrl("/hello", true)
//                    .failureUrl("/auth/login?error")
//                    .and()
//                    .logout()
//                    .logoutUrl("/logout")
//                    .logoutSuccessUrl("/auth/login");
//        }


    //    *******************  Если используем свой AuthProvider
//    private final AuthProviderImpl authProvider;
//    @Autowired
//    public SecurityConfig(AuthProviderImpl authProvider) {
//        this.authProvider = authProvider;
//    }
//protected void config(AuthenticationManagerBuilder auth){
//    auth.authenticationProvider(authProvider);
//}
//}
