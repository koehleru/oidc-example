package de.uko.oidc.adapter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/api/preauth")
public class PreLoginController {

    private AuthenticationManager authenticationManager;

    @GetMapping
    public ResponseEntity<String> preAuth(final HttpServletRequest request) {
        var token = new UsernamePasswordAuthenticationToken("user", "password");
        var authentication = authenticationManager.authenticate(token);

        var sc = SecurityContextHolder.getContext();
        sc.setAuthentication(authentication);

        var session = request.getSession();
        session.setAttribute("SPRING_SECURITY_CONTEXT", sc);

        return ResponseEntity.ok().build();
    }
}