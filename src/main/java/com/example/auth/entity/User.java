package com.example.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An account that can authenticate.
 *
 * <p>Only the data the API contracts actually use is stored: identity, username and the password
 * hash. Migrations are forward-only, so an unused profile column would be permanent.
 */
@Entity
@Table(name = "users")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 50)
	private String username;

	/** Always a hash produced by a {@code PasswordEncoder}; plaintext must never reach this field. */
	@Column(name = "password_hash", nullable = false, length = 100)
	private String passwordHash;

	/**
	 * No cascade: roles are shared reference data. Lazy because most requests only need the
	 * username; the authentication path loads roles and permissions explicitly through
	 * {@code UserRepository.findByUsername}.
	 */
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(
			name = "user_roles",
			joinColumns = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new LinkedHashSet<>();

	protected User() {
		// Required by JPA.
	}

	public User(String username, String passwordHash) {
		this.username = username;
		this.passwordHash = passwordHash;
	}

	public Long getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public void setPasswordHash(String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public Set<Role> getRoles() {
		return Collections.unmodifiableSet(roles);
	}

	public void addRole(Role role) {
		roles.add(role);
	}

	/**
	 * The permissions this user holds, flattened across all of their roles.
	 *
	 * <p>This is what the security layer turns into granted authorities: endpoints check a
	 * permission, not a role, so a new role becomes effective without touching any endpoint.
	 */
	public Set<Permission> getPermissions() {
		Set<Permission> permissions = new LinkedHashSet<>();
		for (Role role : roles) {
			permissions.addAll(role.getPermissions());
		}
		return Collections.unmodifiableSet(permissions);
	}

	/** Never includes the password hash: entities get logged by accident, hashes must not leak. */
	@Override
	public String toString() {
		return "User{id=" + id + ", username='" + username + "'}";
	}
}
