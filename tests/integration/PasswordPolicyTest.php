<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Password_Policy;
use PHPUnit\Framework\TestCase;

/**
 * The breach API is faked through pre_http_request, so the suite needs no network.
 */
final class PasswordPolicyTest extends TestCase {

	/** @var callable|null */
	private $fake;

	protected function tearDown(): void {
		if ( $this->fake ) {
			remove_filter( 'pre_http_request', $this->fake );
		}
	}

	public function test_a_short_password_is_refused(): void {
		$this->fake_breach_api( 200, '' );

		$this->assertStringContainsString( '12', (string) ( new Password_Policy() )->problem( 'Short1!' ) );
	}

	public function test_a_long_unbreached_password_is_accepted(): void {
		$this->fake_breach_api( 200, "0018A45C4D1DEF81644B54AB7F969B88D65:3\n" );

		$this->assertNull( ( new Password_Policy() )->problem( 'correct horse battery staple 42' ) );
	}

	public function test_a_breached_password_is_refused_and_only_the_hash_prefix_is_sent(): void {
		$password = 'password1234';
		$hash     = strtoupper( sha1( $password ) );
		$this->fake_breach_api( 200, "00000000000000000000000000000000000:0\n" . substr( $hash, 5 ) . ":42\n", $url );

		$this->assertNotNull( ( new Password_Policy() )->problem( $password ) );
		$this->assertStringEndsWith( '/range/' . substr( $hash, 0, 5 ), $url );
	}

	public function test_a_padding_entry_with_count_zero_is_not_a_breach(): void {
		$password = 'a padded but unbreached passphrase';
		$this->fake_breach_api( 200, substr( strtoupper( sha1( $password ) ), 5 ) . ":0\n" );

		$this->assertNull( ( new Password_Policy() )->problem( $password ) );
	}

	public function test_an_api_outage_accepts_the_password_and_reports_it(): void {
		$this->fake_breach_api( 503, '' );
		$events   = [];
		$listener = static function ( string $event ) use ( &$events ): void {
			$events[] = $event;
		};
		add_action( 'bp/hardening/event', $listener );

		try {
			$problem = ( new Password_Policy() )->problem( 'a long password during an outage' );
		} finally {
			remove_action( 'bp/hardening/event', $listener );
		}

		$this->assertNull( $problem );
		$this->assertContains( 'breach_check_unavailable', $events );
	}

	public function test_the_rest_api_refuses_a_weak_password(): void {
		$this->fake_breach_api( 200, '' );
		$request = new \WP_REST_Request( 'POST', '/wp/v2/users' );
		$request->set_param( 'password', 'short' );

		$result = ( new Password_Policy() )->on_rest_insert( new \stdClass(), $request );

		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}

	public function test_the_profile_form_refuses_a_weak_password_on_the_password_field(): void {
		$this->fake_breach_api( 200, '' );
		$errors = new \WP_Error();

		( new Password_Policy() )->on_profile_update( $errors, true, (object) [ 'user_pass' => 'short' ] );

		$this->assertSame( 'pass1', $errors->get_error_data( 'bp_weak_password' )['form-field'] );
	}

	private function fake_breach_api( int $status, string $body, ?string &$url = null ): void {
		$this->fake = static function ( $pre, $args, $requested ) use ( $status, $body, &$url ) {
			$url = $requested;
			return [
				'headers'  => [],
				'body'     => $body,
				'response' => [ 'code' => $status, 'message' => '' ],
				'cookies'  => [],
			];
		};
		add_filter( 'pre_http_request', $this->fake, 10, 3 );
	}
}
