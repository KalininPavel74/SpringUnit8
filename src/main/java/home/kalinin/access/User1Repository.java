package home.kalinin.access;
import home.kalinin.access.security.User1;
import org.springframework.data.jpa.repository.JpaRepository;

public interface User1Repository extends JpaRepository<User1, Long> {

  User1 findByUsername(String username);
  
}
