<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Hardening;
use PHPUnit\Framework\TestCase;

final class HardeningTest extends TestCase {

	public static function tearDownAfterClass(): void {
		Fixtures::clean();
	}

	protected function tearDown(): void {
		wp_set_current_user( 0 );
	}

	public function test_an_unknown_username_and_a_wrong_password_give_the_same_error(): void {
		$user    = Fixtures::user();
		$unknown = wp_authenticate( Fixtures::identifier( 'bp-nobody-' . wp_generate_password( 6, false ) ), 'x' );
		$wrong   = wp_authenticate( Fixtures::identifier( $user->user_login ), 'not-the-password' );

		$this->assertSame( 'bp_invalid_credentials', $unknown->get_error_code() );
		$this->assertSame( $unknown->get_error_code(), $wrong->get_error_code() );
		$this->assertSame( $unknown->get_error_message(), $wrong->get_error_message() );
	}

	public function test_an_unknown_email_gives_the_same_error_as_an_unknown_username(): void {
		$error = wp_authenticate( Fixtures::identifier( 'bp-nobody-' . wp_generate_password( 6, false ) . '@example.test' ), 'x' );

		$this->assertSame( 'bp_invalid_credentials', $error->get_error_code() );
	}

	public function test_errors_that_reveal_nothing_are_kept(): void {
		$locked = new \WP_Error( 'bp_login_locked', 'Too many login attempts.' );
		$empty  = new \WP_Error( 'empty_password', 'The password field is empty.' );

		$this->assertSame( $locked, ( new Hardening() )->generic_login_error( $locked ) );
		$this->assertSame( $empty, ( new Hardening() )->generic_login_error( $empty ) );
	}

	public function test_anonymous_visitors_get_no_user_routes(): void {
		wp_set_current_user( 0 );
		$routes = ( new Hardening() )->restrict_rest_user_endpoints(
			[
				'/wp/v2/users'                => [],
				'/wp/v2/users/(?P<id>[\d]+)'  => [],
				'/wp/v2/users/me'             => [],
				'/wp/v2/posts'                => [],
			]
		);

		$this->assertSame( [ '/wp/v2/posts' ], array_keys( $routes ) );
	}

	public function test_logged_in_editors_keep_the_user_routes_for_the_author_picker(): void {
		wp_set_current_user( Fixtures::user( 'editor' )->ID );
		$routes = ( new Hardening() )->restrict_rest_user_endpoints( [ '/wp/v2/users' => [] ] );

		$this->assertArrayHasKey( '/wp/v2/users', $routes );
	}

	public function test_xmlrpc_and_pingbacks_are_off(): void {
		$methods = apply_filters( 'xmlrpc_methods', [ 'pingback.ping' => 'x', 'pingback.extensions.getPingbacks' => 'x', 'wp.getPosts' => 'x' ] );

		$this->assertFalse( apply_filters( 'xmlrpc_enabled', true ) );
		$this->assertSame( [ 'wp.getPosts' ], array_keys( $methods ) );
		$this->assertArrayNotHasKey( 'X-Pingback', apply_filters( 'wp_headers', [ 'X-Pingback' => 'x' ] ) );
	}

	public function test_application_passwords_are_unavailable(): void {
		$this->assertFalse( wp_is_application_passwords_available() );
	}

	public function test_the_core_version_is_stripped_from_asset_urls_but_other_versions_stay(): void {
		$core   = 'https://bp-sandbox.ddev.site/wp/wp-includes/css/x.css?ver=' . get_bloginfo( 'version' );
		$plugin = 'https://bp-sandbox.ddev.site/wp-content/plugins/p/x.css?ver=1.2.3';

		$this->assertStringNotContainsString( 'ver=', ( new Hardening() )->strip_core_version( $core ) );
		$this->assertSame( $plugin, ( new Hardening() )->strip_core_version( $plugin ) );
	}

	public function test_the_users_sitemap_is_removed(): void {
		$this->assertFalse( ( new Hardening() )->remove_users_sitemap( new \stdClass(), 'users' ) );
	}
}
