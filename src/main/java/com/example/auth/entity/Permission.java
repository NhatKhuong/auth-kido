package com.example.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.Objects;

/**
 * A single authority that can be granted through a role, for example {@code USER_READ}.
 *
 * <p>The name is the string {@code @PreAuthorize("hasAuthority('...')")} checks against, so it is
 * part of the system contract and is seeded by migration, not by application code.
 */
@Entity
@Table(name = "permissions")
public class Permission {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 50)
	private String name;

	protected Permission() {
		// Required by JPA.
	}

	public Permission(String name) {
		this.name = name;
	}

	public Long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	/**
	 * Equality is by name, the natural key, because a user's permissions are the union of the
	 * permissions of several roles: identity equality would let the same permission appear twice in
	 * that union when the roles were loaded by different persistence contexts.
	 */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		return other instanceof Permission permission && Objects.equals(name, permission.name);
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
