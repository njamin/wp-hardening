<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fixed-window counters in transients, for login, lost-password and the client
 * plugin's public forms and REST routes.
 *
 * Two concurrent requests can both read the same count, so a limit may let one or two
 * extra hits through. That is acceptable for throttling; it is not a quota.
 */
final class Rate_Limit {

	/**
	 * Counts one hit and says whether the caller is still under the limit.
	 */
	public static function hit( string $bucket, string $key, int $limit, int $window ): bool {
		return self::count( $bucket, $key, $window ) <= $limit;
	}

	/**
	 * Counts one hit and returns the count in the current window.
	 */
	public static function count( string $bucket, string $key, int $window ): int {
		$name  = self::name( $bucket, $key );
		$count = (int) get_transient( $name ) + 1;
		set_transient( $name, $count, $window );

		return $count;
	}

	/**
	 * Whether the limit is already reached, without counting a hit.
	 */
	public static function exceeded( string $bucket, string $key, int $limit ): bool {
		return (int) get_transient( self::name( $bucket, $key ) ) >= $limit;
	}

	/**
	 * Clears a counter, e.g. to unblock an IP from the runbook.
	 */
	public static function reset( string $bucket, string $key ): void {
		delete_transient( self::name( $bucket, $key ) );
	}

	private static function name( string $bucket, string $key ): string {
		return 'bp_rl_' . substr( md5( $bucket ), 0, 8 ) . '_' . Security_Event::pseudonym( $key );
	}
}
