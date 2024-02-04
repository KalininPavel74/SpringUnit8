package home.kalinin.aspect;

import home.kalinin.access.security.User1;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

public class HTTPInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String userData = Optional.ofNullable(request)
                .map(request_ -> request_.getUserPrincipal())
                .filter(val -> val instanceof UsernamePasswordAuthenticationToken)
                .map(val -> ((UsernamePasswordAuthenticationToken)val).getPrincipal())
                .filter(val -> val instanceof User1)
                .map(user1 -> (User1)user1)
                .map(user1 -> user1.getAuthorities() + " " + user1.getUsername() + " " + user1.getFullname())
                .orElse("Пользователь не идентифицирован.");

        System.out.println("[3) HTTP Interceptor pre] Кто: " + request.getRemoteUser() + " " + userData
                + "; Куда: " + request.getRequestURL() + "; Контроллер: " + handler);
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) {
        System.out.println("[3) HTTP Interceptor post] ======================");
    }
}
