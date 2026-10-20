<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The plugins listed in `BP_PROTECTED_PLUGINS` (basenames, e.g. `acme-portal/acme-portal.php`)
 * can't be deactivated from wp-admin. The hardening itself is a must-use plugin, which
 * wp-admin can't deactivate anyway. WP-CLI still can, for recovery.
 */
final class Plugin_Guard {

	public function register(): void {
		add_filter( 'plugin_action_links', [ $this, 'remove_deactivate_link' ], 10, 2 );
		add_filter( 'pre_update_option_active_plugins', [ $this, 'keep_protected_active' ], 10, 2 );
	}

	/**
	 * @param array<string, string> $actions
	 * @return array<string, string>
	 */
	public function remove_deactivate_link( array $actions, string $plugin_file ): array {
		if ( in_array( $plugin_file, $this->protected_plugins(), true ) ) {
			unset( $actions['deactivate'] );
		}

		return $actions;
	}

	/**
	 * Bulk actions and crafted requests bypass the links, so the option write is the real guard.
	 *
	 * @param mixed $new_value
	 * @param mixed $old_value
	 */
	public function keep_protected_active( $new_value, $old_value ): mixed {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ! is_array( $new_value ) || ! is_array( $old_value ) ) {
			return $new_value;
		}

		$removed = array_intersect( array_diff( $old_value, $new_value ), $this->protected_plugins() );
		if ( [] === $removed ) {
			return $new_value;
		}

		Security_Event::emit( 'protected_plugin_deactivation_refused', [ 'plugins' => array_values( $removed ) ] );

		return array_values( array_unique( array_merge( $new_value, $removed ) ) );
	}

	/**
	 * @return list<string>
	 */
	private function protected_plugins(): array {
		return defined( 'BP_PROTECTED_PLUGINS' ) ? array_values( (array) BP_PROTECTED_PLUGINS ) : [];
	}
}
