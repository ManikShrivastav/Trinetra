<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;      // import LoginController
use App\Http\Controllers\DashboardController;  // import DashboardController
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Auth\RegisterController;

Route::get('/register', [RegisterController::class,'showRegistration'])->name('register');
Route::post('/register', [RegisterController::class,'register'])->name('register.post');

Route::get('/', function () {
    return view('loading'); // loading.blade.php
});

Route::get('/check-session', function () {
    try {
        return response()->json(['logged_in' => Auth::check()]);
    } catch (\Exception $e) {
        Log::error('Check-session error: ' . $e->getMessage(), [
            'exception' => $e
        ]);

        return response()->json([
            'error' => config('app.debug') ? $e->getMessage() : 'Server error'
        ], 500);
    }
});

Route::get('/login', [LoginController::class, 'showLogin'])->name('login');
Route::post('/login', [LoginController::class, 'login'])->name('login.post');
Route::get('/dashboard', [DashboardController::class, 'showDashboard'])->name('dashboard');

Route::view('/500', '500')->name('500');

