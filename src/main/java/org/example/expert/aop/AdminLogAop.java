package org.example.expert.aop;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.CodeSignature;
import org.example.expert.config.JwtUtil;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j(topic = "AdminLogAop:")
@Aspect
@Component
@RequiredArgsConstructor
public class AdminLogAop {
    private final JwtUtil jwtUtil;

    @Pointcut("execution(* org.example.expert.domain.user.controller.UserAdminController.changeUserRole(..))")
    private void changeUserRole() {
    }

    @Pointcut("execution(* org.example.expert.domain.comment.controller.CommentAdminController.deleteComment(..))")
    private void deleteComment() {
    }

    @Before("changeUserRole() || deleteComment()")
    public Object execute(ProceedingJoinPoint joinPoint) throws Throwable {
        LocalDateTime now = LocalDateTime.now();
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String url = request.getRequestURI();
        Long userId = getRequestUserId(request);

        log.info("요청 시간: " + now);
        log.info("요청 유저: " + userId);
        log.info("요청 url: " + url);

        return joinPoint.proceed();
    }

    @After("changeUserRole() || deleteComment()")
    public Object execute2(ProceedingJoinPoint joinPoint) throws Throwable {
        Map<String, Object> body = params(joinPoint);
        LocalDateTime now = LocalDateTime.now();

        log.info("응답 시간: " + now);
        log.info("응답 body: " + body);

        return joinPoint.proceed();
    }

    private Map<String, Object> params(JoinPoint joinPoint) {
        CodeSignature codeSignature = (CodeSignature) joinPoint.getSignature();
        String[] parameterNames = codeSignature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        Map<String, Object> params = new HashMap<>();
        for (int idx = 0; idx < parameterNames.length; idx++) {
            params.put(parameterNames[idx], args[idx]);
        }
        return params;
    }

    private Long getRequestUserId(HttpServletRequest request) {
        String bearerJwt = request.getHeader("Authorization");
        if (bearerJwt == null) {
            log.info("JWT 토큰이 필요합니다.");
            return null;
        }

        // JWT 유효성 검사와 claims 추출
        String jwt = jwtUtil.substringToken(bearerJwt);
        Claims claims = jwtUtil.extractClaims(jwt);
        if (claims == null) {
            log.info("잘못된 JWT 토큰입니다.");
            return null;
        }

        return Long.parseLong(claims.getSubject());
    }
}
