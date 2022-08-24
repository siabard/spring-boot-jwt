package net.izelon.spring_jwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import net.izelon.spring_jwt.models.ERole;
import net.izelon.spring_jwt.models.Role;
import net.izelon.spring_jwt.models.User;
import net.izelon.spring_jwt.paylods.request.LoginRequest;
import net.izelon.spring_jwt.paylods.request.SignupRequest;
import net.izelon.spring_jwt.paylods.response.MessageResponse;
import net.izelon.spring_jwt.paylods.response.UserInfoResponse;
import net.izelon.spring_jwt.repositories.RoleRepository;
import net.izelon.spring_jwt.repositories.UserRepository;
import net.izelon.spring_jwt.services.UserDetailsImpl;
import net.izelon.spring_jwt.utils.JwtTokenUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetail = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetail.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());
        String jwt = jwtTokenUtil.generateToken(userDetail);
        return ResponseEntity.ok().body(new UserInfoResponse(loginRequest.getUsername(), jwt, roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> register(@RequestBody SignupRequest signup) {
        if (userRepository.existsByEmail(signup.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: email is taken"));
        }

        if (userRepository.existsByUsername(signup.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: username is taken"));
        }

        // create new user without roles
        User user = new User(signup.getUsername(), signup.getEmail(), passwordEncoder.encode(signup.getPassword()));
        Set<Role> userRoles = new HashSet<>();
        Set<String> roles = signup.getRoles();

        if (roles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found : User"));
            userRoles.add(userRole);
        } else {
            roles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found : Admin"));
                        userRoles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found : Moderator"));
                        userRoles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found : User"));
                        userRoles.add(userRole);
                }
            });
        }

        user.setRoles(userRoles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered success"));

    }
}
