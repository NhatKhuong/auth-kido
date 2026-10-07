package com.example.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.assertj.core.api.Assertions;

@DataJpaOnPostgres
class UserRepositoryTest {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Test
	void findsByUsernameWithRolesAndPermissionsLoaded() {
		User admin = userRepository.findByUsername("admin").orElseThrow();

		// Touching the graph is the assertion: the entity graph has to have fetched both levels.
		assertThat(admin.getRoles()).extracting(Role::getName).containsExactly("ROLE_ADMIN");
		assertThat(admin.getPermissions()).extracting(Permission::getName).contains("USER_READ");
	}

	@Test
	void returnsEmptyForAnUnknownUsername() {
		assertThat(userRepository.findByUsername("nobody")).isEmpty();
	}

	@Test
	void reportsWhetherAUsernameIsTaken() {
		assertThat(userRepository.existsByUsername("admin")).isTrue();
		assertThat(userRepository.existsByUsername("nobody")).isFalse();
	}

	/**
	 * A new account can be given an existing role without the role being copied: roles are shared
	 * reference data, so the mapping must not cascade into them.
	 */
	@Test
	void assigningAnExistingRoleCreatesOnlyAMappingRow() {
		Role roleUser = roleRepository.findByName("ROLE_USER").orElseThrow();
		User created = new User("tester", "$2a$10$notarealhashnotarealhashnotarealhashnotarealhashnotareal");
		created.addRole(roleUser);

		User saved = userRepository.saveAndFlush(created);

		assertThat(saved.getId()).isNotNull();
		assertThat(roleRepository.findAll()).hasSize(2);
		assertThat(userRepository.findByUsername("tester").orElseThrow().getPermissions())
				.extracting(Permission::getName)
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE");
	}

	/** Usernames identify an account at login, so the database must not allow two of them. */
	@Test
	void rejectsADuplicateUsername() {
		User duplicate = new User("admin", "$2a$10$notarealhashnotarealhashnotarealhashnotarealhashnotareal");

		Assertions.assertThatThrownBy(() -> userRepository.saveAndFlush(duplicate))
				.isInstanceOf(DataIntegrityViolationException.class);
	}
}
