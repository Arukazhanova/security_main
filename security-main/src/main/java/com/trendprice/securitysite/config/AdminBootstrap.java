package com.trendprice.securitysite.config;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.Role;
import com.trendprice.securitysite.user.RoleName;
import com.trendprice.securitysite.user.RoleRepository;
import com.trendprice.securitysite.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component
public class AdminBootstrap implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;

    public AdminBootstrap(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AdminProperties adminProperties
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminProperties = adminProperties;
    }

    @Override
    public void run(String... args) {
        if (!adminProperties.isCreateOnStartup()) {
            return;
        }

        Role userRole = roleRepository.findByName(resolveUserRoleName())
                .orElseGet(() -> roleRepository.save(new Role(resolveUserRoleName())));

        Role adminRole = roleRepository.findByName(resolveAdminRoleName())
                .orElseGet(() -> roleRepository.save(new Role(resolveAdminRoleName())));

        Optional<AppUser> existingAdminByEmail = userRepository.findByEmail(adminProperties.getEmail());

        if (existingAdminByEmail.isPresent()) {
            AppUser admin = existingAdminByEmail.get();

            Set<Role> roles = admin.getRoles();
            if (roles == null) {
                roles = new HashSet<>();
                admin.setRoles(roles);
            }

            boolean changed = false;

            if (!roles.contains(userRole)) {
                roles.add(userRole);
                changed = true;
            }

            if (!roles.contains(adminRole)) {
                roles.add(adminRole);
                changed = true;
            }

            if (!Boolean.TRUE.equals(admin.getEmailVerified())) {
                admin.setEmailVerified(true);
                changed = true;
            }

            if (!admin.isEnabled()) {
                admin.setEnabled(true);
                changed = true;
            }

            if (Boolean.TRUE.equals(admin.getBlocked())) {
                admin.setBlocked(false);
                changed = true;
            }

            if (changed) {
                userRepository.save(admin);
            }

            return;
        }

        Set<Role> adminRoles = new HashSet<>();
        adminRoles.add(userRole);
        adminRoles.add(adminRole);

        AppUser admin = new AppUser(
                adminProperties.getUsername(),
                adminProperties.getEmail(),
                passwordEncoder.encode(adminProperties.getPassword()),
                adminRoles
        );

        admin.setEmailVerified(true);
        admin.setEnabled(true);
        admin.setBlocked(false);

        userRepository.save(admin);
    }

    private RoleName resolveUserRoleName() {
        try {
            return RoleName.valueOf("ROLE_USER");
        } catch (IllegalArgumentException e) {
            return RoleName.valueOf("USER");
        }
    }

    private RoleName resolveAdminRoleName() {
        try {
            return RoleName.valueOf("ROLE_ADMIN");
        } catch (IllegalArgumentException e) {
            return RoleName.valueOf("ADMIN");
        }
    }
}