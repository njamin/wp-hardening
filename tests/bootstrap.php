<?php
/**
 * Loads the sandbox site (BP_WP_LOAD overrides the path) with the package active.
 *
 * Tests seed their own fixtures and remove them: the database is the sandbox's, and
 * nothing rolls back between tests.
 */

require dirname( __DIR__ ) . '/vendor/autoload.php';

// Constants the controls read once; set here so every test sees the same configuration.
define( 'BP_TRUSTED_PROXIES', [ '10.0.0.0/8' ] );
define( 'BP_PROTECTED_PLUGINS', [ 'two-factor/two-factor.php' ] );
define( 'BP_2FA_EXEMPT_USERS', [ 'bp-test-admin' ] );

$_SERVER['HTTP_HOST']      = 'bp-sandbox.ddev.site';
$_SERVER['SERVER_NAME']    = 'bp-sandbox.ddev.site';
$_SERVER['REQUEST_URI']    = '/';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTPS']          = 'on';

$wp_load = getenv( 'BP_WP_LOAD' ) ?: '/var/www/html/sandbox/web/wp/wp-load.php';
if ( ! file_exists( $wp_load ) ) {
	fwrite( STDERR, "wp-load.php not found at {$wp_load}. Run the suite inside DDEV, or set BP_WP_LOAD.\n" );
	exit( 1 );
}

require $wp_load;
require_once ABSPATH . 'wp-admin/includes/user.php';

if ( ! class_exists( \BP\Hardening\Plugin::class ) || ! has_filter( 'xmlrpc_enabled' ) ) {
	fwrite( STDERR, "The hardening isn't active on the site (is BP_DISABLE_HARDENING set?).\n" );
	exit( 1 );
}

// In a long-lived PHPUnit process a wp_die() or exit ends the whole run with exit code 0:
// a false green. Turn them into exceptions the tests can assert on.
foreach ( [ 'wp_die_handler', 'wp_die_ajax_handler', 'wp_die_json_handler', 'wp_die_xmlrpc_handler' ] as $bp_filter ) {
	add_filter(
		$bp_filter,
		static fn() => static function ( $message = '' ): never {
			throw new \RuntimeException( 'wp_die() during a test: ' . ( is_scalar( $message ) ? $message : wp_json_encode( $message ) ) );
		},
		0
	);
}
add_filter(
	'wp_redirect',
	static function ( string $location ): never {
		throw new \BP\Hardening\Tests\Redirect_Exception( $location );
	},
	0
);
