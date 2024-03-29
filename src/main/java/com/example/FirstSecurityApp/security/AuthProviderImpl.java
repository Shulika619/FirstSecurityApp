//package com.example.FirstSecurityApp.security;
//
//import com.example.FirstSecurityApp.services.PersonDetailsService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import java.util.Collections;
//
//
//// Аутентификация: свой AuthProviderImpl
//
//@Component
//public class AuthProviderImpl implements AuthenticationProvider {
//
//    private final PersonDetailsService personDetailsService;
//
//    @Autowired
//    public AuthProviderImpl(PersonDetailsService personDetailsService) {
//        this.personDetailsService = personDetailsService;
//    }
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String name = authentication.getName();
//        UserDetails userDetails =personDetailsService.loadUserByUsername(name);
//        String password = authentication.getCredentials().toString();
//        if(!password.equals(userDetails.getPassword()))
//            throw new BadCredentialsException("Incorect password");
//        return new UsernamePasswordAuthenticationToken(userDetails,password, Collections.emptyList());
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return true;
//    }
//}
