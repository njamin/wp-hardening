<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A field people never see and bots fill in, for the client plugin's public forms.
 *
 *     echo Honeypot::field();                // inside the <form>
 *     if ( Honeypot::is_bot() ) { … }        // in the handler, before any work
 */
final class Honeypot {

	private const FIELD = 'bp_website';

	public static function field(): string {
		// Off-screen rather than display:none, which some bots detect; out of the tab order
		// and hidden from screen readers so no person fills it in.
		return sprintf(
			'<div aria-hidden="true" style="position:absolute;left:-9999px"><label for="%1$s">%2$s</label><input type="text" id="%1$s" name="%1$s" value="" tabindex="-1" autocomplete="off"></div>',
			esc_attr( self::FIELD ),
			esc_html__( 'Leave this field empty', 'bp-hardening' )
		);
	}

	public static function is_bot(): bool {
		$filled = '' !== trim( (string) wp_unslash( $_POST[ self::FIELD ] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the caller's handler checks the nonce
		if ( $filled ) {
			Security_Event::emit( 'honeypot_filled' );
		}

		return $filled;
	}
}
