<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;

class ScanController extends Controller
{
    public function index()
    {
        if (!Session::has('user_id')) {
            return redirect()->route('login');
        }

        $userId = Session::get('user_id');
        $user = DB::table('praveshjankari')
            ->join('roles', 'praveshjankari.role_id', '=', 'roles.id')
            ->select('praveshjankari.*', 'roles.name as role_name')
            ->where('praveshjankari.id', $userId)
            ->first();

        if (!$user) {
            Session::forget(['user_id', 'user_name', 'role_id']);
            return redirect()->route('login')->with('error', 'Session expired or user not found.');
        }

        return view('scan', compact('user'));
    }
}
