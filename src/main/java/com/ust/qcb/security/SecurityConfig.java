package com.ust.qcb.security;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
                        // ── Public endpoints ──
                        // ✅ FIX: removed "/api/users/delete/**" and "/api/payments/**" from this
                        // list — they were wide open to anyone, even without logging in.
                        // ✅ FIX: "/api/services/**" restricted to GET only so browsing services
                        // stays public, but adding a service (POST) is no longer accidentally public too.
                        .requestMatchers("/api/auth/**",
                                "/api/users/get/**",
                                "/api/bookings/date/**",
                                "/api/reviews/service/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/services/**").permitAll()

                        .requestMatchers("/api/users/**",
                                "/api/providers/**").hasRole("USER")
                        .requestMatchers("/api/providers/get/**",
                                "/api/providers/delete/**").hasRole("USER")
                        .requestMatchers("/api/services/provider/**").hasRole("USER")
                        .requestMatchers("/api/bookings/book/**",
                                "/api/bookings/confirm-slot/**",
                                "/api/bookings/delete/**").hasRole("USER")
                        // ✅ FIX: A user needs to view their own booking after payment
                        // to retrieve their OTP — this was locked to PROVIDER-only before,
                        // which would have blocked the booking-confirmed screen entirely.
                        .requestMatchers("/api/bookings/get/**").hasAnyRole("USER", "PROVIDER")
                        // ✅ NEW: The user verifies the OTP with their on-site provider.
                        .requestMatchers("/api/bookings/verify-otp/**").hasRole("USER")
                        // ✅ FIX: payments now correctly require login (USER role) again —
                        // this rule used to be unreachable because of the old blanket permitAll above.
                        .requestMatchers("/api/payments/pay/**",
                                "/api/payments/booking/**").hasRole("USER")
                        .requestMatchers("/api/reviews/add/**").hasRole("USER")
                        // ✅ NEW: AI chat assistant requires login too — keeps the
                        // Anthropic API key usage tied to authenticated users only,
                        // and prevents random bots from hammering your AI quota.
                        .requestMatchers("/api/ai/chat").hasRole("USER")
                        .requestMatchers("/api/providers/**").hasRole("PROVIDER")
                        .requestMatchers("/api/services/add/**").hasRole("PROVIDER")
                        .requestMatchers("/api/bookings/user/**",
                                "/api/bookings/provider/**").hasRole("PROVIDER")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ✅ CORS configuration bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // ⚠️ TODO before deploying: replace with your deployed frontend URL
        // e.g. "https://your-portfolio-quickconnect.vercel.app"
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
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
