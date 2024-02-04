package home.kalinin.aspect;

import home.kalinin.access.security.User1;
import lombok.extern.java.Log;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Log
public class TrackUserActionAspect {
    @Around("@annotation(home.kalinin.aspect.TrackUserAction)")
        public Object logExecutionTime(ProceedingJoinPoint joinPoint) throws Throwable {
        User1 user1 = ((User1) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        long start = System.currentTimeMillis();
        Object proceed = joinPoint.proceed();
        long executionTime = System.currentTimeMillis() - start;
        System.out.println("[1) @Around @TrackUserAction] Время: " + executionTime + " ms; Кто: "+ user1.getAuthorities()+" "+user1.getUsername()+" "+user1.getFullname()+" Что: " +joinPoint.getSignature().getName()+" - "+joinPoint.getSignature());
        return proceed;
    }
    @Before("execution(String home.kalinin.controllers.HomeController.getHome(org.springframework.ui.Model))")
    public void logBeforeMethodCall(JoinPoint joinPoint) {
        System.out.println("[2) @Before execution] Метод " + joinPoint.getSignature().getName() + " был вызван");
    }
}
