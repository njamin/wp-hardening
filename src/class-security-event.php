<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Publishes security events for the project's Logger to record.
 *
 * The package doesn't depend on a Logger: it fires `bp/hardening/event`, and the
 * Logger from njamin/wp-core subscribes to it.
 */
final class Security_Event {

	/**
	 * @param string               $event   e.g. `failed_login`, `lockout`.
	 * @param array<string, mixed> $context Never a plaintext username or e-mail: use self::pseudonym().
	 */
	public static function emit( string $event, array $context = [] ): void {
		$context['ip'] = Client_Ip::get();
		$context['ua'] = mb_substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 );

		do_action( 'bp/hardening/event', $event, $context );
	}

	/**
	 * Keyed hash of an identifier. A plain SHA-256 of a username can be reversed by
	 * hashing guesses; without the site key it can't.
	 */
	public static function pseudonym( string $identifier ): string {
		$key = defined( 'BP_LOG_KEY' ) && BP_LOG_KEY ? (string) BP_LOG_KEY : wp_salt( 'auth' );

		return hash_hmac( 'sha256', strtolower( trim( $identifier ) ), $key );
	}
}
