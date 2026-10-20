<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Login_Throttle;
use BP\Hardening\Rate_Limit;
use PHPUnit\Framework\TestCase;

final class LoginThrottleTest extends TestCase {

	private const IP = '198.51.100.77';

	private array $server;

	protected function setUp(): void {
		$this->server           = $_SERVER;
		$_SERVER['REMOTE_ADDR'] = self::IP;
		Rate_Limit::reset( 'login_ip', self::IP );
	}

	protected function tearDown(): void {
		Rate_Limit::reset( 'login_ip', self::IP );
		$_SERVER = $this->server;
	}

	public function test_twenty_failures_from_one_ip_block_it(): void {
		$throttle = new Login_Throttle();

		for ( $i = 0; $i < 19; $i++ ) {
			$throttle->count_failure();
		}
		$this->assertFalse( is_wp_error( $throttle->check( null ) ) );

		$throttle->count_failure();
		$blocked = $throttle->check( null );
		$this->assertTrue( is_wp_error( $blocked ) );
		$this->assertSame( 'bp_login_throttled', $blocked->get_error_code() );
	}

	public function test_the_block_is_reported_once_not_on_every_further_attempt(): void {
		$throttle = new Login_Throttle();
		$events   = 0;
		$listener = static function ( string $event ) use ( &$events ): void {
			$events += 'login_ip_throttled' === $event ? 1 : 0;
		};
		add_action( 'bp/hardening/event', $listener );

		try {
			for ( $i = 0; $i < 30; $i++ ) {
				$throttle->count_failure();
			}
		} finally {
			remove_action( 'bp/hardening/event', $listener );
		}

		$this->assertSame( 1, $events );
	}
}
