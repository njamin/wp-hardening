<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Locks a username, whatever the IP, after repeated failures.
 *
 * An edge rate limit is per IP, so rotating residential proxies defeat it; locking the
 * username slot doesn't depend on where the attempts come from. A browser that has
 * already logged in as that user carries a signed device cookie and is exempt, so
 * someone who knows a username can't keep its owner out.
 *
 * Thresholds: `BP_LOGIN_USER_THRESHOLD` (5), `BP_LOGIN_USER_WINDOW` and
 * `BP_LOGIN_USER_LOCK` (1800 s each).
 * Unlock by hand: `wp transient delete bp_login_lock_<hmac>` (see RUNBOOK.md).
 */
final class Username_Lockout {

	private const DEVICE_COOKIE   = 'bp_known_device';
	private const DEVICE_LIFETIME = 180 * DAY_IN_SECONDS;

	public function register(): void {
		// Priority 25 runs after the password check (20), so the lock also refuses a correct password.
		add_filter( 'authenticate', [ $this, 'check_lock' ], 25, 2 );
		add_action( 'wp_login_failed', [ $this, 'on_fail' ] );
		add_action( 'wp_login', [ $this, 'on_success' ], 10, 2 );
	}

	public function check_lock( mixed $user, mixed $username ): mixed {
		$username = (string) $username;
		if ( '' === $username || $this->is_exempt( $username ) ) {
			return $user;
		}

		if ( get_transient( $this->key( $username, 'lock' ) ) ) {
			return new \WP_Error(
				'bp_login_locked',
				esc_html__( 'Too many login attempts. Please try again later.', 'bp-hardening' )
			);
		}

		return $user;
	}

	public function on_fail( string $username ): void {
		if ( '' === $username || $this->is_exempt( $username ) ) {
			return;
		}

		$fails_key = $this->key( $username, 'fails' );
		$count     = (int) get_transient( $fails_key ) + 1;
		set_transient( $fails_key, $count, $this->setting( 'BP_LOGIN_USER_WINDOW', 30 * MINUTE_IN_SECONDS ) );

		if ( $count < $this->setting( 'BP_LOGIN_USER_THRESHOLD', 5 ) ) {
			return;
		}

		$lock = $this->setting( 'BP_LOGIN_USER_LOCK', 30 * MINUTE_IN_SECONDS );
		set_transient( $this->key( $username, 'lock' ), time() + $lock, $lock );
		delete_transient( $fails_key );

		Security_Event::emit( 'lockout', [ 'user' => Security_Event::pseudonym( $username ) ] );
	}

	public function on_success( string $user_login, \WP_User $user ): void {
		// The user may have typed their e-mail, which has its own counter.
		foreach ( array_unique( [ $user_login, $user->user_email ] ) as $id ) {
			delete_transient( $this->key( $id, 'fails' ) );
			delete_transient( $this->key( $id, 'lock' ) );
		}

		$this->set_device_cookie( $user->ID );
	}

	private function is_exempt( string $username ): bool {
		$user = get_user_by( 'login', $username ) ?: get_user_by( 'email', $username );
		if ( ! $user ) {
			return false;
		}

		// On a single site is_super_admin() is true for every administrator, which would
		// exempt the accounts most worth attacking; only Multisite network admins are exempt.
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}

		return $this->has_device_cookie( $user->ID );
	}

	private function set_device_cookie( int $user_id ): void {
		// WP-CLI and REST logins have no browser to remember.
		if ( headers_sent() ) {
			return;
		}

		$expires = time() + self::DEVICE_LIFETIME;
		$value   = $user_id . '|' . $expires . '|' . $this->device_signature( $user_id, $expires );

		setcookie(
			self::DEVICE_COOKIE . '_' . $user_id,
			$value,
			[
				'expires'  => $expires,
				'path'     => SITECOOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]
		);
	}

	private function has_device_cookie( int $user_id ): bool {
		$raw   = (string) wp_unslash( $_COOKIE[ self::DEVICE_COOKIE . '_' . $user_id ] ?? '' );
		$parts = explode( '|', $raw );
		if ( 3 !== count( $parts ) ) {
			return false;
		}

		[ $id, $expires, $signature ] = $parts;
		if ( (int) $id !== $user_id || (int) $expires < time() ) {
			return false;
		}

		return hash_equals( $this->device_signature( $user_id, (int) $expires ), $signature );
	}

	private function device_signature( int $user_id, int $expires ): string {
		// Bound to the password hash, so a password change invalidates every device cookie.
		$user = get_userdata( $user_id );
		$pass = $user ? $user->user_pass : '';

		return hash_hmac( 'sha256', $user_id . '|' . $expires . '|' . $pass, wp_salt( 'secure_auth' ) );
	}

	private function key( string $username, string $suffix ): string {
		// The transient name must stay under 172 characters: prefix + 64 hex chars.
		return 'bp_login_' . $suffix . '_' . Security_Event::pseudonym( $username );
	}

	private function setting( string $constant, int $default ): int {
		return defined( $constant ) ? (int) constant( $constant ) : $default;
	}
}
