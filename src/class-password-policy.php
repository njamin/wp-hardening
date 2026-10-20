<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Every password set through WordPress has at least `BP_PASSWORD_MIN_LENGTH`
 * characters (12) and isn't in a known breach.
 *
 * The breach check uses Have I Been Pwned's range API: only the first five hex
 * characters of the SHA-1 leave the server (k-anonymity). If the API can't be reached
 * the password is accepted, so an outage never blocks a reset; the event is reported.
 * `BP_BREACHED_PASSWORD_CHECK` false switches the check off (offline CI).
 * WP-CLI is not covered: whoever has a shell can already change the database.
 */
final class Password_Policy {

	public function register(): void {
		add_action( 'user_profile_update_errors', [ $this, 'on_profile_update' ], 10, 3 );
		add_action( 'validate_password_reset', [ $this, 'on_reset' ], 10, 2 );
		add_filter( 'rest_pre_insert_user', [ $this, 'on_rest_insert' ], 10, 2 );
	}

	public function on_profile_update( \WP_Error $errors, bool $update, \stdClass $user ): void {
		if ( empty( $user->user_pass ) ) {
			return;
		}

		$problem = $this->problem( (string) $user->user_pass );
		if ( null !== $problem ) {
			$errors->add( 'bp_weak_password', $problem, [ 'form-field' => 'pass1' ] );
		}
	}

	public function on_reset( \WP_Error $errors ): void {
		$password = (string) wp_unslash( $_POST['pass1'] ?? '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- core verified the reset key; a password is never sanitised
		if ( '' === $password ) {
			return;
		}

		$problem = $this->problem( $password );
		if ( null !== $problem ) {
			$errors->add( 'bp_weak_password', $problem );
		}
	}

	public function on_rest_insert( mixed $prepared_user, \WP_REST_Request $request ): mixed {
		$password = $request->get_param( 'password' );
		if ( ! is_string( $password ) || '' === $password ) {
			return $prepared_user;
		}

		$problem = $this->problem( $password );

		return null === $problem ? $prepared_user : new \WP_Error( 'bp_weak_password', $problem, [ 'status' => 400 ] );
	}

	/**
	 * Why the password is refused, or null when it is accepted.
	 */
	public function problem( string $password ): ?string {
		$min = defined( 'BP_PASSWORD_MIN_LENGTH' ) ? (int) BP_PASSWORD_MIN_LENGTH : 12;
		if ( mb_strlen( $password ) < $min ) {
			/* translators: %d: minimum number of characters. */
			return sprintf( esc_html__( 'The password must have at least %d characters.', 'bp-hardening' ), $min );
		}

		if ( $this->is_breached( $password ) ) {
			return esc_html__( 'This password has appeared in a data breach. Please choose another one.', 'bp-hardening' );
		}

		return null;
	}

	private function is_breached( string $password ): bool {
		if ( defined( 'BP_BREACHED_PASSWORD_CHECK' ) && ! BP_BREACHED_PASSWORD_CHECK ) {
			return false;
		}

		$hash     = strtoupper( sha1( $password ) );
		$response = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . substr( $hash, 0, 5 ),
			[
				'timeout' => 3,
				'headers' => [ 'Add-Padding' => 'true' ],
			]
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			Security_Event::emit( 'breach_check_unavailable' );
			return false;
		}

		$suffix = substr( $hash, 5 );
		foreach ( explode( "\n", wp_remote_retrieve_body( $response ) ) as $line ) {
			[ $candidate, $count ] = array_pad( explode( ':', trim( $line ) ), 2, '0' );
			// Padding entries have a count of 0 and are not real breaches.
			if ( $candidate === $suffix && (int) $count > 0 ) {
				return true;
			}
		}

		return false;
	}
}
