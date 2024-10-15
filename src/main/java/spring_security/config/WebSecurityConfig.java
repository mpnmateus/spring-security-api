package spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

    @Autowired
    private SecurityDatabaseService securityService;

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(securityService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/managers").hasRole("MANAGERS")
                        .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin                      // Configuração para form-based authentication
                        .loginPage("/login")                               // Definindo a rota da página de login
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.sendRedirect("/login");
                        })
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                )
                .sessionManagement(session -> session
                        .sessionFixation().newSession()
                );

        return http.build();
    }
    /*
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

     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
