<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Illuminate\Support\ServiceProvider;

/**
 * HeliosPermissionsServiceProvider — auto-discovered by Laravel via
 * composer.json's extra.laravel.providers. Publishes the config and
 * binds PermissionClientInterface as a singleton.
 */
final class HeliosPermissionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/helios-permissions.php',
            'helios-permissions',
        );

        $this->app->singleton(PermissionClientInterface::class, function ($app) {
            $config = $app['config']->get('helios-permissions', []);
            $r = Factory::create($config);
            // Close on application shutdown — Laravel calls any
            // callables registered via $this->app->terminating().
            $this->app->terminating(static function () use ($r) {
                ($r->close)();
            });
            return $r->client;
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/helios-permissions.php' => config_path('helios-permissions.php'),
            ], 'helios-permissions-config');
        }
    }
}
