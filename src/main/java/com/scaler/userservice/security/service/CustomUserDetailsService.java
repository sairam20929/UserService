package com.scaler.userservice.security.service;

import com.scaler.userservice.model.User;
import com.scaler.userservice.repository.UserRepository;
import com.scaler.userservice.security.model.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        return new CustomUserDetails(userOptional.get());
    }

}
