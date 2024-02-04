package home.kalinin;

import home.kalinin.access.User1Repository;
import home.kalinin.access.security.Admin;
import home.kalinin.access.security.SecurityConfig;
import home.kalinin.access.security.User1;
import home.kalinin.models.Dict;
import home.kalinin.repository.DictRepository;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@Aspect
@Slf4j
@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
    @Bean
    public CommandLineRunner dataLoader(DictRepository noteRepository, PasswordEncoder passwordEncoder, User1Repository userRepo) {
        return new CommandLineRunner() {
            @Override
            public void run(String... args) throws Exception {
                noteRepository.save(new Dict("Словарь 1", 1));
                noteRepository.save(new Dict("Словарь 2", 22));
                noteRepository.save(new Dict("Словарь 3", 33.33));
                noteRepository.save(new Dict("Словарь 4", 4.4));

                User1 user1 = new User1("1",passwordEncoder.encode("1"),"Пользователь по умолчанию");
                userRepo.save(user1);
            }
        };
    }
}