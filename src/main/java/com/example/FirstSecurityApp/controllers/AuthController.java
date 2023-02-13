package com.example.FirstSecurityApp.controllers;

import com.example.FirstSecurityApp.dto.PersonDTO;
import com.example.FirstSecurityApp.models.Person;
import com.example.FirstSecurityApp.security.JWTUtil;
import com.example.FirstSecurityApp.services.RegistrationService;
import com.example.FirstSecurityApp.util.PersonValidator;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final PersonValidator personValidator;
    private final JWTUtil jwtUtil;
    private final ModelMapper modelMapper;

    @Autowired
    public AuthController(RegistrationService registrationService, PersonValidator personValidator, JWTUtil jwtUtil, ModelMapper modelMapper) {
        this.registrationService = registrationService;
        this.personValidator = personValidator;
        this.jwtUtil = jwtUtil;
        this.modelMapper = modelMapper;
    }

    @GetMapping("/login")
    public String loginPage(){
        return "auth/login";
    }

    @GetMapping("/registration")
    public String registrationPage(@ModelAttribute("person")Person person){
        return "auth/registration";
    }

    @PostMapping("/registration")
    public Map<String,String> performRegistration(@RequestBody @Valid PersonDTO personDTO, BindingResult bindingResult){
        Person person = convertToPerson(personDTO);
        personValidator.validate(person,bindingResult);
        if(bindingResult.hasErrors())
            return Map.of("message","Ошибка!"); // быстрое решение (правильн кидать свое исключение)
        registrationService.register(person);
        String token = jwtUtil.generateToken(person.getUsername());
        return Map.of("jwt-token",token);
    }
    public Person convertToPerson(PersonDTO personDTO){
        return this.modelMapper.map(personDTO,Person.class);
    }
}
