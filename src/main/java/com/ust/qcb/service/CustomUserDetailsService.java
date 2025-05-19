package com.ust.qcb.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ust.qcb.entity.ServiceProvider;
import com.ust.qcb.entity.Users;
import com.ust.qcb.repository.ServiceProviderRepository;
import com.ust.qcb.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
    private ServiceProviderRepository serviceProviderRepository;
	
	@Override
    public UserDetails loadUserByUsername(String email) {
        Users user = userRepository.findByEmail(email);

        if (user != null) {
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getEmail())
                    .password(user.getPassword())
                    .roles(user.getRole().name())
                    .build();
        }
    
	    ServiceProvider provider = serviceProviderRepository.findByEmail(email);
	    if (provider != null) {
	        return org.springframework.security.core.userdetails.User.builder()
	                .username(provider.getEmail())
	                .password(provider.getPassword())
	                .roles(provider.getRole().name())
	                .build();
	    }
	    
	    throw new UsernameNotFoundException("User or Service Provider not found with email: " + email);
    }
}