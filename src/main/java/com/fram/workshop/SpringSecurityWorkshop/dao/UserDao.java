package com.fram.workshop.SpringSecurityWorkshop.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;


@Repository
public class UserDao {

    private final static List<UserDetails> APP_USERS_LIST = Arrays.asList(
            new User(
                    "mwas@gmail.com",
                    "mwas12345" ,
                    //Collections.singleton(New SimpleGrantedAuthority('ROLE_ADMIN')),
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))


            ),
            new User(
                    "doe@gmail.com",
                    "mwas12345" ,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))

            )
    );

    public UserDetails findUserByEmail(String email){
        return  APP_USERS_LIST
                .stream()
                .filter(user-> user.getUsername().equals(email))
                .findFirst()
                .orElseThrow(()-> new UsernameNotFoundException("No user found with provided email"));
    }
}
