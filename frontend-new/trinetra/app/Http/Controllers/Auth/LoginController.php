<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Session;

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

        $roles = DB::table('roles')->get();
        return view('auth.login', compact('roles')); // This will load resources/views/auth/login.blade.php
    }

    // Handle login form POST
    public function login(Request $request)
    {
       
       $request->validate([
            'userid' => 'required|string',
            'password' => 'required|string',
            'role_id' => 'required|integer',
        ]);

        // Fetch user by userid
        $user = DB::table('praveshjankari')->where('userid', $request->userid)->first();

        if (!$user) {
            return back()->withErrors(['login_error' => 'User ID does not exist']);
        }

        // Password check
        if (!Hash::check($request->password, $user->password)) {
            return back()->withErrors(['login_error' => 'Incorrect password']);
        }

        // Role check
        if ($user->role_id != $request->role_id) {
            return back()->withErrors(['login_error' => 'Selected role is incorrect']);
        }

        // All good → create session
        Session::put('user_id', $user->id);
        Session::put('user_name', $user->name);
        Session::put('role_id', $user->role_id);

        return redirect()->route('dashboard');
    }

    // Logout
    public function logout()
    {
        Session::flush();
        return redirect()->route('login');
    }
}
