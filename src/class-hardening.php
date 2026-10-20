<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WordPress-level controls of the security baseline: attack surface, username
 * enumeration and version disclosure.
 */
final class Hardening {

	public function register(): void {
		// xmlrpc_enabled only disables the authenticated methods; the pingback ones stay
		// reachable (SSRF and reflected DDoS) unless removed separately.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', [ $this, 'remove_pingback_methods' ] );
		add_filter( 'wp_headers', [ $this, 'strip_pingback_header' ] );

		// Application passwords bypass 2FA. An integration that needs them defines the constant.
		if ( ! ( defined( 'BP_ALLOW_APPLICATION_PASSWORDS' ) && BP_ALLOW_APPLICATION_PASSWORDS ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		add_filter( 'rest_endpoints', [ $this, 'restrict_rest_user_endpoints' ] );
		add_action( 'init', [ $this, 'remove_rest_discovery_for_anonymous' ] );
		// Priority 0: before redirect_canonical turns ?author=N into a redirect to the login slug.
		add_action( 'template_redirect', [ $this, 'block_author_enumeration' ], 0 );
		add_filter( 'wp_sitemaps_add_provider', [ $this, 'remove_users_sitemap' ], 10, 2 );

		// Last in the chain, so it also rewrites what the password check (20) returned.
		add_filter( 'authenticate', [ $this, 'generic_login_error' ], 99 );
		add_action( 'wp_login_failed', [ $this, 'record_failed_login' ] );

		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'style_loader_src', [ $this, 'strip_core_version' ] );
		add_filter( 'script_loader_src', [ $this, 'strip_core_version' ] );
	}

	/**
	 * @param array<string, mixed> $methods
	 * @return array<string, mixed>
	 */
	public function remove_pingback_methods( array $methods ): array {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );

		return $methods;
	}

	/**
	 * @param array<string, string> $headers
	 * @return array<string, string>
	 */
	public function strip_pingback_header( array $headers ): array {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	/**
	 * Logged-in users keep the routes: the block editor's author picker reads them as an
	 * editor, who has no `list_users`.
	 *
	 * @param array<string, mixed> $endpoints
	 * @return array<string, mixed>
	 */
	public function restrict_rest_user_endpoints( array $endpoints ): array {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array_keys( $endpoints ) as $route ) {
			if ( str_starts_with( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	public function remove_rest_discovery_for_anonymous(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		remove_action( 'wp_head', 'rest_output_link_wp_head' );
		remove_action( 'template_redirect', 'rest_output_link_header', 11 );
	}

	public function block_author_enumeration(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		$probe = isset( $_GET['author'] ) && '' !== $_GET['author']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only check, no state change
		if ( $probe || is_author() ) {
			status_header( 403 );
			nocache_headers();
			exit;
		}
	}

	public function remove_users_sitemap( mixed $provider, string $name ): mixed {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * "Unknown user" and "wrong password" become one message, so the form can't tell which
	 * accounts exist. Lockout and throttle messages stay: they are given for unknown
	 * usernames too.
	 */
	public function generic_login_error( mixed $user ): mixed {
		$leaky = [ 'invalid_username', 'invalid_email', 'incorrect_password' ];
		if ( ! is_wp_error( $user ) || [] === array_intersect( $user->get_error_codes(), $leaky ) ) {
			return $user;
		}

		return new \WP_Error( 'bp_invalid_credentials', esc_html__( 'Invalid credentials. Please try again.', 'bp-hardening' ) );
	}

	public function record_failed_login( string $username ): void {
		Security_Event::emit( 'failed_login', [ 'user' => Security_Event::pseudonym( $username ) ] );
	}

	public function strip_core_version( string $src ): string {
		$version = get_bloginfo( 'version' );
		if ( str_contains( $src, 'ver=' . $version ) ) {
			$src = remove_query_arg( 'ver', $src );
		}

		return $src;
	}
}
