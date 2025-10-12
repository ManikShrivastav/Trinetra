<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
// use Illuminate\Support\Facades\Auth;

class DashboardController extends Controller
{
    
    public function showDashboard()
    {
        // Check if user is logged in
        if (!Session::has('user_id')) {
            return redirect()->route('login');
        }

        $userId = Session::get('user_id');

        // Fetch user details from database
        $user = DB::table('praveshjankari')
                    ->join('roles', 'praveshjankari.role_id', '=', 'roles.id')
                    ->select('praveshjankari.*', 'roles.name as role_name')
                    ->where('praveshjankari.id', $userId)
                    ->first();

                    // ✅ Handle invalid/missing user
        if (!$user) {
            Session::forget(['user_id', 'user_name', 'role_id']);
            return redirect()->route('login')->with('error', 'Session expired or user not found.');
        }
        return view('dashboard', compact('user'));
    }

    
}

