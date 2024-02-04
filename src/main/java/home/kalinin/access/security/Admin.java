package home.kalinin.access.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

public final class Admin extends User1 {

    private static Admin admin;
    private Admin(String username, String password, String fullname) {
        super(username, password, fullname);
    }

    public static Admin getInstance(String username, String password) {
        if(admin == null)
            admin = new Admin(username, password,"Администратор");
        return admin;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}
