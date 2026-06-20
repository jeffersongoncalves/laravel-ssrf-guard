<?php

namespace JeffersonGoncalves\SsrfGuard\Tests;

use JeffersonGoncalves\SsrfGuard\SsrfGuardServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app)
    {
        return [
            SsrfGuardServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testing');
    }
}
