<?php

namespace JeffersonGoncalves\SsrfGuard;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsrfGuardServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-ssrf-guard')
            ->hasConfigFile('ssrf-guard');
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(SsrfGuard::class);
    }
}
