package home.kalinin.access.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import home.kalinin.access.User1Repository;

@Configuration
@Slf4j
public class SecurityConfig {
    public static final String ADMIN_ = "admin";

    @Bean
    @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
    public Admin getAdmin(User1Repository userRepo) {
        log.info("Admin getAdmin()");
        Admin admin = Admin.getInstance(ADMIN_, passwordEncoder().encode("password"));
        // заблокировать пользователем использование логина admin (т.к. User1 не хранит роли)
        userRepo.save(new User1(admin.getUsername(),admin.getPassword(),admin.getFullname()));
        return admin;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(User1Repository userRepo, Admin admin) {
        return username -> {   // через лямбда обеспечивает метод UserDetails loadUserByUsername(String username)
            if (username.equals(ADMIN_))
                return admin;
            User1 user1 = userRepo.findByUsername(username);
            if (user1 != null) {
                return user1;
            }
            throw new UsernameNotFoundException(
                    "User1 '" + username + "' not found");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/styles.css", "/favicon.ico"
                                , "/", "/home", "/login", "/registration"
                                , "/h2-console/**"
                                , "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "v3/api-docs/**").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN") // @PreAuthorize("hasRole('ADMIN')") в месте с @EnableMethodSecurity на классе
                        .requestMatchers("/dicts").hasAnyRole("USER")
                        .requestMatchers("/api/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                        //.anyRequest().permitAll()
                )
                .formLogin(form -> form.loginPage("/login").defaultSuccessUrl("/home", true))
                .logout((logout) -> logout.logoutSuccessUrl("/home"))
                .csrf((csrf) -> csrf.ignoringRequestMatchers("/h2-console/**")) // с этим тестирование соединения проходит в н2
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin())); // ЗАРАБОТАЛО ДЛЯ н2, но исключение csrf тоже нужно
        // http.headers(headers -> headers.disable());   // ЗАРАБОТАЛО ДЛЯ н2   ОТКЛЮЧИТЬ ВСЕ ЗАГОЛОВКИ БЕЗОПАСНОСТИ
        return http.build();
    }
}
