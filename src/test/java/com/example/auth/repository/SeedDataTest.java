package com.example.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Pins the seed data down, because it is a contract rather than a convenience: the permission
 * names are what {@code @PreAuthorize("hasAuthority('...')")} will check in backlog 0006/0007, and
 * the demo password hashes are what login in backlog 0004 will verify.
 *
 * <p>Every set is asserted for exact equality, not containment. A seed that grants one permission
 * too many is a privilege escalation and has to fail here, where it is cheap to see.
 */
@DataJpaOnPostgres
class SeedDataTest {

	/**
	 * Mirrors the plaintexts documented in .env.example. Only the hashes are in the migration, so
	 * without this the two could drift apart and nothing would notice until login failed.
	 */
	private static final String ADMIN_PASSWORD = "admin12345";
	private static final String USER_PASSWORD = "user12345";

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PermissionRepository permissionRepository;

	@Autowired
	private UserRepository userRepository;

	@Test
	void seedsExactlyTwoRoles() {
		assertThat(roleRepository.findAll())
				.extracting(Role::getName)
				.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
	}

	@Test
	void seedsExactlyFourPermissions() {
		assertThat(permissionRepository.findAll())
				.extracting(Permission::getName)
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE", "USER_READ", "USER_MANAGE");
	}

	@Test
	void roleUserGrantsExactlyAccountReadAndPasswordChange() {
		assertThat(permissionNamesOfRole("ROLE_USER"))
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE");
	}

	@Test
	void roleAdminGrantsExactlyTheFourPermissions() {
		assertThat(permissionNamesOfRole("ROLE_ADMIN"))
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE", "USER_READ", "USER_MANAGE");
	}

	@Test
	void seedsExactlyTwoDemoUsers() {
		assertThat(userRepository.findAll())
				.extracting(User::getUsername)
				.containsExactlyInAnyOrder("admin", "user");
	}

	@ParameterizedTest
	@CsvSource({ "admin, ROLE_ADMIN", "user, ROLE_USER" })
	void demoUserHasExactlyItsRole(String username, String expectedRole) {
		assertThat(requireUser(username).getRoles())
				.extracting(Role::getName)
				.containsExactly(expectedRole);
	}

	@Test
	void adminPermissionsAreDerivedFromItsRole() {
		assertThat(permissionNamesOfUser("admin"))
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE", "USER_READ", "USER_MANAGE");
	}

	@Test
	void userPermissionsAreDerivedFromItsRole() {
		assertThat(permissionNamesOfUser("user"))
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE");
	}

	/**
	 * The one check that proves the seeded hashes are usable. Everything else here can be green
	 * while login in backlog 0004 still fails, and a wrong hash is almost impossible to trace back
	 * from there.
	 */
	@ParameterizedTest
	@CsvSource({ "admin, " + ADMIN_PASSWORD, "user, " + USER_PASSWORD })
	void demoPasswordHashVerifiesAgainstTheDocumentedPlaintext(String username, String plaintext) {
		String storedHash = requireUser(username).getPasswordHash();

		assertThat(new BCryptPasswordEncoder().matches(plaintext, storedHash)).isTrue();
	}

	@ParameterizedTest
	@CsvSource({ "admin, " + ADMIN_PASSWORD, "user, " + USER_PASSWORD })
	void demoPasswordIsStoredOnlyAsABcryptHash(String username, String plaintext) {
		String storedHash = requireUser(username).getPasswordHash();

		assertThat(storedHash).doesNotContain(plaintext).startsWith("$2a$10$").hasSize(60);
	}

	private Set<String> permissionNamesOfRole(String roleName) {
		Role role = roleRepository.findByName(roleName).orElseThrow();
		return role.getPermissions().stream().map(Permission::getName).collect(Collectors.toSet());
	}

	private Set<String> permissionNamesOfUser(String username) {
		return requireUser(username).getPermissions().stream()
				.map(Permission::getName)
				.collect(Collectors.toSet());
	}

	private User requireUser(String username) {
		return userRepository.findByUsername(username).orElseThrow();
	}
}
