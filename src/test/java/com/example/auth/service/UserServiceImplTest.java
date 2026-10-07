package com.example.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.dto.request.ChangePasswordRequest;
import com.example.auth.dto.response.AccountResponse;
import com.example.auth.dto.response.UserSummaryResponse;
import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.exception.InvalidCurrentPasswordException;
import com.example.auth.exception.UnauthorizedException;
import com.example.auth.repository.UserRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Account read and password change business rules of architecture 01-overview.md section 9.
 *
 * <p>A real {@link BCryptPasswordEncoder} is used rather than a mock, for the same reason as in
 * {@code AuthenticationServiceImplTest}: the claims under test are "the stored value is a hash of
 * the new password" and "a wrong current password does not verify", and a stubbed encoder would
 * let both pass without any hashing being right.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

	private static final long USER_ID = 7L;
	private static final String CURRENT_PASSWORD = "user12345";
	private static final String NEW_PASSWORD = "a-brand-new-password";

	@Mock
	private UserRepository userRepository;

	private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	private UserServiceImpl service;
	private User account;
	private String originalHash;

	@BeforeEach
	void setUp() {
		service = new UserServiceImpl(userRepository, passwordEncoder);
		account = user("user", CURRENT_PASSWORD);
		originalHash = account.getPasswordHash();
	}

	@Test
	void currentAccountReturnsIdUsernameRolesAndPermissions() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.of(account));

		AccountResponse response = service.getCurrentAccount(USER_ID);

		assertThat(response.id()).isEqualTo(USER_ID);
		assertThat(response.username()).isEqualTo("user");
		assertThat(response.roles()).containsExactly("ROLE_USER");
		// Sorted, not in insertion order: the response is a contract, a Set's order is not.
		assertThat(response.permissions()).containsExactly("ACCOUNT_READ", "PASSWORD_CHANGE");
	}

	@Test
	void currentAccountResponseCarriesNothingSensitive() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.of(account));

		String rendered = service.getCurrentAccount(USER_ID).toString();

		// The record's own toString is what a log statement or an assertion would print; it must be
		// as free of the hash as the serialised body is.
		assertThat(rendered)
				.doesNotContain(CURRENT_PASSWORD)
				.doesNotContain(originalHash)
				.doesNotContain("password", "passwordHash", "tokenHash");
	}

	@Test
	void currentAccountIsUnauthorizedWhenTheTokenNamesAnAccountThatIsGone() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.getCurrentAccount(USER_ID))
				.isInstanceOf(UnauthorizedException.class)
				.hasFieldOrPropertyWithValue("code", "UNAUTHORIZED")
				.hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED);
	}

	@Test
	void changePasswordStoresAHashOfTheNewPasswordAndNeverThePlaintext() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.of(account));

		service.changePassword(USER_ID, new ChangePasswordRequest(CURRENT_PASSWORD, NEW_PASSWORD));

		String stored = savedAccount().getPasswordHash();
		// The three claims of "hashed before it is stored": not the plaintext, a BCrypt value, and
		// one that actually verifies the new password.
		assertThat(stored).isNotEqualTo(NEW_PASSWORD).startsWith("$2a$");
		assertThat(passwordEncoder.matches(NEW_PASSWORD, stored)).isTrue();
		assertThat(passwordEncoder.matches(CURRENT_PASSWORD, stored)).isFalse();
		assertThat(stored).isNotEqualTo(originalHash);
	}

	@Test
	void changePasswordIsRejectedWhenTheCurrentPasswordIsWrong() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.of(account));

		assertThatThrownBy(() -> service.changePassword(
				USER_ID, new ChangePasswordRequest("not-the-current-password", NEW_PASSWORD)))
				.isInstanceOf(InvalidCurrentPasswordException.class)
				.hasFieldOrPropertyWithValue("code", "INVALID_CURRENT_PASSWORD")
				// 400, not 401: the access token is still perfectly valid.
				.hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST);

		// Nothing was written, and the account still verifies its old password.
		verify(userRepository, never()).save(any());
		assertThat(account.getPasswordHash()).isEqualTo(originalHash);
		assertThat(passwordEncoder.matches(CURRENT_PASSWORD, account.getPasswordHash())).isTrue();
	}

	@Test
	void changePasswordIsUnauthorizedWhenTheTokenNamesAnAccountThatIsGone() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.changePassword(
				USER_ID, new ChangePasswordRequest(CURRENT_PASSWORD, NEW_PASSWORD)))
				.isInstanceOf(UnauthorizedException.class);

		verify(userRepository, never()).save(any());
	}

	@Test
	void noPasswordValueReachesTheLogOnEitherASuccessfulOrARejectedChange() {
		when(userRepository.findWithRolesAndPermissionsById(USER_ID)).thenReturn(Optional.of(account));
		Logger serviceLogger = (Logger) LoggerFactory.getLogger(UserServiceImpl.class);
		ListAppender<ILoggingEvent> captured = new ListAppender<>();
		captured.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		captured.start();
		Level originalLevel = serviceLogger.getLevel();
		// TRACE, so a debug statement that happened to print the request object would be caught.
		serviceLogger.setLevel(Level.TRACE);
		serviceLogger.addAppender(captured);
		try {
			assertThatThrownBy(() -> service.changePassword(
					USER_ID, new ChangePasswordRequest("a-wrong-current-password", NEW_PASSWORD)))
					.isInstanceOf(InvalidCurrentPasswordException.class);
			service.changePassword(USER_ID, new ChangePasswordRequest(CURRENT_PASSWORD, NEW_PASSWORD));
		}
		finally {
			serviceLogger.detachAppender(captured);
			serviceLogger.setLevel(originalLevel);
			captured.stop();
		}

		// Both branches log, so "nothing leaked" is not vacuously true.
		assertThat(captured.list).hasSizeGreaterThanOrEqualTo(2);
		assertThat(captured.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
				.doesNotContain(CURRENT_PASSWORD)
				.doesNotContain(NEW_PASSWORD)
				.doesNotContain("a-wrong-current-password")
				.doesNotContain(originalHash));
	}

	@Test
	void theRequestAndTheRejectionNeverPrintAPassword() {
		ChangePasswordRequest request = new ChangePasswordRequest(CURRENT_PASSWORD, NEW_PASSWORD);

		// Request objects end up in exception messages and debug logs, so the record's own
		// toString has to be safe by construction rather than by nobody printing it.
		assertThat(request.toString()).doesNotContain(CURRENT_PASSWORD, NEW_PASSWORD);
		assertThat(new InvalidCurrentPasswordException().getMessage())
				.isNotBlank()
				.doesNotContain(CURRENT_PASSWORD, NEW_PASSWORD);
	}

	@Test
	void listUsersReturnsEveryAccountWithItsRolesSorted() {
		User admin = account("admin", 1L, "ROLE_ADMIN", "ROLE_USER");
		User plain = account("user", 2L, "ROLE_USER");
		when(userRepository.findAllByOrderByIdAsc()).thenReturn(List.of(admin, plain));

		List<UserSummaryResponse> listed = service.listUsers();

		assertThat(listed).containsExactly(
				// Roles sorted although they were added ROLE_USER first: the response is a
				// contract and a Set's iteration order is not.
				new UserSummaryResponse(1L, "admin", List.of("ROLE_ADMIN", "ROLE_USER")),
				new UserSummaryResponse(2L, "user", List.of("ROLE_USER")));
	}

	@Test
	void listUsersPreservesTheRepositoryOrder() {
		when(userRepository.findAllByOrderByIdAsc()).thenReturn(List.of(
				account("first", 1L, "ROLE_USER"),
				account("second", 2L, "ROLE_USER"),
				account("third", 3L, "ROLE_USER")));

		// Oldest first is part of the contract, so the service must not re-sort or re-group.
		assertThat(service.listUsers()).extracting(UserSummaryResponse::username)
				.containsExactly("first", "second", "third");
	}

	@Test
	void listUsersNeverExposesCredentialMaterial() {
		User listed = account("admin", 1L, "ROLE_ADMIN");
		when(userRepository.findAllByOrderByIdAsc()).thenReturn(List.of(listed));

		// The record's own toString is what ends up in a log or an assertion message, so the
		// absence of the hash has to be a property of the type, not of the caller.
		assertThat(service.listUsers().toString())
				.doesNotContain(listed.getPasswordHash())
				.doesNotContain("$2a$")
				.doesNotContain("password");
	}

	@Test
	void listUsersReturnsAnEmptyListWhenThereAreNoAccounts() {
		when(userRepository.findAllByOrderByIdAsc()).thenReturn(List.of());

		// Empty, not null: the endpoint must still answer 200 with a JSON array.
		assertThat(service.listUsers()).isEmpty();
	}

	/** An account with the given id and roles; roles are added in reverse order on purpose. */
	private User account(String username, long id, String... roleNames) {
		User created = new User(username, passwordEncoder.encode("irrelevant-for-listing"));
		for (int index = roleNames.length - 1; index >= 0; index--) {
			created.addRole(new Role(roleNames[index]));
		}
		ReflectionTestUtils.setField(created, "id", id);
		return created;
	}

	private User savedAccount() {
		ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
		verify(userRepository).save(saved.capture());
		return saved.getValue();
	}

	private User user(String username, String plaintextPassword) {
		Role role = new Role("ROLE_USER");
		// Added in reverse alphabetical order so the sorted response is not a coincidence.
		role.addPermission(new Permission("PASSWORD_CHANGE"));
		role.addPermission(new Permission("ACCOUNT_READ"));
		User created = new User(username, passwordEncoder.encode(plaintextPassword));
		created.addRole(role);
		ReflectionTestUtils.setField(created, "id", USER_ID);
		return created;
	}
}
