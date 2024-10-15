package spring_security.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity  // Substitui @EnableGlobalMethodSecurity no Spring Security 6.x
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()  // Substitui antMatchers() por requestMatchers()
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        .requestMatchers("/managers").hasRole("MANAGERS")
                        .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults()) // Usamos autenticação básica
                .logout(logout -> logout                      // Configuração para logout
                        .logoutUrl("/logout")                     // URL para logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            // Define a resposta após logout
                            response.setStatus(HttpServletResponse.SC_OK);   // Define o status da resposta HTTP como OK (200)
                            response.sendRedirect("/login");                 // Redireciona para a página de login
                        })
                        .invalidateHttpSession(true)              // Invalida a sessão
                        .deleteCookies("JSESSIONID")              // Deleta o cookie de sessão
                        .clearAuthentication(true)                // Limpa a autenticação
                )
                .sessionManagement(session -> session
                        .sessionFixation().newSession()
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user")
                .password("password")
                .roles("USERS")
                .build();

        UserDetails user2 = User.withUsername("manager")
                .password("password")
                .roles("MANAGERS")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();  // Utiliza {noop} para senha sem criptografia
    }
}
