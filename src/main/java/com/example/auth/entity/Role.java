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
import java.util.Objects;
import java.util.Set;

/**
 * A named bundle of permissions, for example {@code ROLE_ADMIN}.
 *
 * <p>Roles exist to group permissions; authorization decisions are made on the permissions
 * themselves (architecture 01-overview.md section 4), so adding a role later is a data change
 * rather than a code change.
 */
@Entity
@Table(name = "roles")
public class Role {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 50)
	private String name;

	/**
	 * No cascade: permissions are shared reference data, so removing a role must drop its grants
	 * (handled by {@code ON DELETE CASCADE} on the join table) and never the permissions.
	 */
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(
			name = "role_permissions",
			joinColumns = @JoinColumn(name = "role_id"),
			inverseJoinColumns = @JoinColumn(name = "permission_id"))
	private Set<Permission> permissions = new LinkedHashSet<>();

	protected Role() {
		// Required by JPA.
	}

	public Role(String name) {
		this.name = name;
	}

	public Long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public Set<Permission> getPermissions() {
		return Collections.unmodifiableSet(permissions);
	}

	public void addPermission(Permission permission) {
		permissions.add(permission);
	}

	/** Equality is by name for the same reason as {@link Permission#equals(Object)}. */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		return other instanceof Role role && Objects.equals(name, role.name);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(name);
	}

	@Override
	public String toString() {
		return name;
	}
}
