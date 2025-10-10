<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    // Show login page
    public function showLogin()
    {
        // If user already logged in → destroy session before showing login page
        if (Auth::check()) {
            Auth::logout();
            session()->invalidate();
            session()->regenerateToken();
        }

        return view('auth.login'); // This will load resources/views/auth/login.blade.php
    }

    // Handle login form POST
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password', 'role');

        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            return redirect()->intended('/dashboard');
        }

        return back()->withErrors([
            'login_error' => 'Invalid credentials, please try again.',
        ]);
    }
}
