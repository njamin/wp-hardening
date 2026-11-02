<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Users in the roles of `BP_2FA_ROLES` (administrator and editor), and the roles a project adds on
 * `bp/hardening/two_factor_roles`, must enrol in two-factor authentication before they can use
 * wp-admin.
 *
 * The Two Factor plugin provides the methods but never forces them; this does. Until a
 * user has enrolled, every admin page redirects them to their profile. On staging and
 * production a missing Two Factor plugin is reported, because the baseline then fails.
 * `BP_2FA_EXEMPT_USERS` (logins, or a prefix ending in `*` for the end-to-end tests' accounts)
 * holds the test admin, and is ignored outside local.
 */
final class Two_Factor_Policy {

	public function register(): void {
		add_action( 'admin_init', [ $this, 'require_enrolment' ] );
		add_action( 'admin_notices', [ $this, 'enrolment_notice' ] );
	}

	public function require_enrolment(): void {
		if ( wp_doing_ajax() || ! $this->must_enrol( wp_get_current_user() ) ) {
			return;
		}

		global $pagenow;
		if ( 'profile.php' === $pagenow ) {
			return;
		}

		wp_safe_redirect( admin_url( 'profile.php#two-factor-options' ) );
		exit;
	}

	public function enrolment_notice(): void {
		if ( ! $this->must_enrol( wp_get_current_user() ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__( 'Your role requires two-factor authentication. Set up a method below to continue.', 'bp-hardening' )
		);
	}

	public function must_enrol( \WP_User $user ): bool {
		if ( ! $user->exists() || [] === array_intersect( $user->roles, $this->roles() ) ) {
			return false;
		}

		if ( 'local' === wp_get_environment_type() && self::exempts( $user->user_login, $this->exempt_users() ) ) {
			return false;
		}

		if ( ! class_exists( '\Two_Factor_Core' ) ) {
			if ( 'local' !== wp_get_environment_type() && 1 === Rate_Limit::count( '2fa_missing', 'site', DAY_IN_SECONDS ) ) {
				Security_Event::emit( 'two_factor_plugin_missing' );
			}
			return false;
		}

		return ! \Two_Factor_Core::is_user_using_two_factor( $user->ID );
	}

	/**
	 * @return list<string>
	 */
	private function roles(): array {
		$roles = defined( 'BP_2FA_ROLES' ) ? array_values( (array) BP_2FA_ROLES ) : [ 'administrator', 'editor' ];
		// The filter only adds: a project forgetting to pass the list on must not free the administrator.
		$added = array_filter( (array) apply_filters( 'bp/hardening/two_factor_roles', $roles ), 'is_string' );

		return array_values( array_unique( [ ...$roles, ...$added ] ) );
	}

	/**
	 * Whether `$exempt` names `$login`: exactly, or by a prefix ending in `*`. A bare `*` names
	 * nobody, so an exemption never covers every account by mistake.
	 *
	 * @param list<string> $exempt
	 */
	public static function exempts( string $login, array $exempt ): bool {
		foreach ( $exempt as $entry ) {
			$prefix = str_ends_with( $entry, '*' ) ? substr( $entry, 0, -1 ) : null;
			if ( null === $prefix ? $entry === $login : '' !== $prefix && str_starts_with( $login, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return list<string>
	 */
	private function exempt_users(): array {
		return defined( 'BP_2FA_EXEMPT_USERS' ) ? array_values( (array) BP_2FA_EXEMPT_USERS ) : [];
	}
}
