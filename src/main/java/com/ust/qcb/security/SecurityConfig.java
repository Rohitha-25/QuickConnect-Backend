package com.ust.qcb.security;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors().and() // ✅ Enable CORS
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**",
                                "/api/users/get/**",
                                "/api/users/delete/**",
                                "/api/services/**",
                                "/api/bookings/date/**",
                                "/api/payments/**",
                                "/api/reviews/service/**").permitAll()
                        .requestMatchers("/api/users/**",
                                "/api/providers/**").hasRole("USER")
                        .requestMatchers("/api/providers/get/**",
                                "/api/providers/delete/**").hasRole("USER")
                        .requestMatchers("/api/services/provider/**").hasRole("USER")
                        .requestMatchers("/api/bookings/book/**",
                                "/api/bookings/delete/**").hasRole("USER")
                        .requestMatchers("/api/payments/pay/**",
                                "/api/payments/booking/**").hasRole("USER")
                        .requestMatchers("/api/reviews/add/**").hasRole("USER")
                        .requestMatchers("/api/providers/**").hasRole("PROVIDER")
                        .requestMatchers("/api/services/add/**").hasRole("PROVIDER")
                        .requestMatchers("/api/bookings/get/**",
                                "/api/bookings/user/**",
                                "/api/bookings/provider/**").hasRole("PROVIDER")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ✅ Add this CORS configuration bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173")); // React dev server
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}