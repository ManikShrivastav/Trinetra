<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\View; // ✅ THIS is the missing import
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //

        View::composer('*', function ($view) {
        if (Session::has('user_id')) {
            $user = DB::table('praveshjankari')
                ->join('roles', 'praveshjankari.role_id', '=', 'roles.id')
                ->select('praveshjankari.name', 'roles.name as role_name')
                ->where('praveshjankari.id', Session::get('user_id'))
                ->first();

            $view->with('user', $user);
        } else {
            $view->with('user', null);
        }
    });
    }
}
