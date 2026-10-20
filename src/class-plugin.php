<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Entry point called by the project's `mu-plugins/bp-loader.php`.
 */
final class Plugin {

	private static bool $booted = false;

	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		// Emergency kill switch: one constant in wp-config.php disables every control without a deploy.
		if ( defined( 'BP_DISABLE_HARDENING' ) && BP_DISABLE_HARDENING ) {
			return;
		}

		// Loaded from vendor/, not wp-content/plugins/, so WordPress can't find the
		// translations on its own.
		add_action( 'init', [ self::class, 'load_translations' ], 0 );

		( new Hardening() )->register();
		( new Username_Lockout() )->register();
		( new Login_Throttle() )->register();
		( new Lost_Password() )->register();
		( new Password_Policy() )->register();
		( new Sessions() )->register();
		( new Uploads() )->register();
		( new Plugin_Guard() )->register();
		( new Two_Factor_Policy() )->register();
	}

	public static function load_translations(): void {
		load_textdomain( 'bp-hardening', dirname( __DIR__ ) . '/languages/bp-hardening-' . determine_locale() . '.mo' );
	}
}
