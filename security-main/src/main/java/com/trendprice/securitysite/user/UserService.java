package com.trendprice.securitysite.user;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository repo;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;

    public UserService(UserRepository repo, RoleRepository roleRepository, PasswordEncoder encoder) {
        this.repo = repo;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
    }

    @Transactional
    public AppUser register(String username, String rawPassword, String email) {
        String normalizedUsername = username.trim();
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        if (repo.existsByUsername(normalizedUsername)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }
        if (repo.existsByEmail(normalizedEmail)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }

        Role userRole = getOrCreateRole(RoleName.USER);
        AppUser user = new AppUser(
                normalizedUsername,
                normalizedEmail,
                encoder.encode(rawPassword),
                Set.of(userRole)
        );
        user.setEmailVerified(false);
        user.setEnabled(false);

        return repo.save(user);
    }

    @Transactional
    public AppUser register(String username, String rawPassword) {
        String normalizedUsername = username.trim();

        if (repo.existsByUsername(normalizedUsername)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }

        Role userRole = getOrCreateRole(RoleName.USER);
        AppUser user = new AppUser(normalizedUsername, encoder.encode(rawPassword), Set.of(userRole));
        return repo.save(user);
    }

    @Transactional(readOnly = true)
    public AppUser findByUsername(String username) {
        return repo.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    @Transactional(readOnly = true)
    public AppUser findByEmail(String email) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        return repo.findByEmail(normalizedEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    @Transactional(readOnly = true)
    public List<AppUser> findAllUsers() {
        return repo.findAll();
    }

    @Transactional
    public void enableUser(AppUser user) {
        user.setEmailVerified(true);
        user.setEnabled(true);
        repo.save(user);
    }

    @Transactional
    public void updatePassword(AppUser user, String rawPassword) {
        user.setPassword(encoder.encode(rawPassword));
        repo.save(user);
    }

    @Transactional
    public void blockUser(Long userId) {
        AppUser user = repo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setBlocked(true);
        repo.save(user);
    }

    @Transactional
    public void unblockUser(Long userId) {
        AppUser user = repo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setBlocked(false);
        repo.save(user);
    }

    @Transactional
    public void changeRole(Long userId, String roleName) {
        AppUser user = repo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        RoleName normalizedRole;
        try {
            normalizedRole = RoleName.valueOf(roleName.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown role: " + roleName);
        }

        Role role = getOrCreateRole(normalizedRole);
        user.setRoles(Set.of(role));
        repo.save(user);
    }

    @Transactional(readOnly = true)
    public Set<String> getRoleNames(String username) {
        return findByUsername(username).getRoles().stream()
                .map(role -> role.getName().name())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    @Transactional(readOnly = true)
    public boolean hasRole(String username, String roleName) {
        RoleName normalizedRole;
        try {
            normalizedRole = RoleName.valueOf(roleName.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown role: " + roleName);
        }

        return findByUsername(username).getRoles().stream()
                .anyMatch(role -> role.getName() == normalizedRole);
    }

    @Transactional
    public Role getOrCreateRole(RoleName roleName) {
        return roleRepository.findByName(roleName)
                .orElseGet(() -> roleRepository.save(new Role(roleName)));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}