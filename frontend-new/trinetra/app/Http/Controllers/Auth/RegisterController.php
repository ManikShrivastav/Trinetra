<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

use Illuminate\Support\Str;

class RegisterController extends Controller
{
    // Show registration form
    public function showRegistration()
    {
        // Get roles from roles table for dropdown
        $roles = DB::table('roles')->get();
        return view('auth.register', compact('roles'));
    }


private function generateUserId(string $name, string $roleName, string $email): string
{
    // Clean and normalize inputs
    $nameOnly = preg_replace('/[^A-Za-z]/', '', $name);
    $roleOnly = preg_replace('/[^A-Za-z]/', '', $roleName);
    $emailLocal = explode('@', $email)[0] ?? '';

    // Last 2 letters of name (pad with X if too short)
    $nameOnly = strtoupper($nameOnly);
    if (strlen($nameOnly) >= 2) {
        $partName = substr($nameOnly, -2);
    } else {
        $partName = str_pad($nameOnly, 2, 'X', STR_PAD_LEFT);
    }

    // First and last letters of role (pad with X if needed)
    $roleOnly = strtoupper($roleOnly);
    $roleFirst = $roleOnly !== '' ? $roleOnly[0] : 'X';
    $roleLast  = strlen($roleOnly) > 1 ? $roleOnly[strlen($roleOnly)-1] : 'X';

    // Two random digits (00 - 99)
    $randDigits = str_pad((string) rand(0, 99), 2, '0', STR_PAD_LEFT);

    // Two random letters from email local-part (fallback to random letters)
    $emailLetters = 'ZZ';
    $localClean = preg_replace('/[^A-Za-z]/', '', $emailLocal);
    if (strlen($localClean) >= 2) {
        // pick two random characters from localClean
        $chars = str_split(strtoupper($localClean));
        shuffle($chars);
        $emailLetters = $chars[0] . $chars[1];
    } elseif (strlen($localClean) === 1) {
        $emailLetters = strtoupper($localClean) . Str::upper(Str::random(1))[0];
    } else {
        // if local part is empty, use two random letters
        $emailLetters = strtoupper(substr(Str::random(2), 0, 2));
    }

    // Compose userid
    $candidate = $partName . $roleFirst . $roleLast . $randDigits . $emailLetters;

    // Ensure uniqueness: if collision, retry a few times (with new digits/letters)
    $tries = 0;
    while (DB::table('praveshjankari')->where('userid', $candidate)->exists()) {
        $tries++;
        if ($tries > 10) {
            // as a fallback append short random suffix
            $candidate .= strtoupper(substr(Str::random(2), 0, 2));
            break;
        }
        $randDigits = str_pad((string) rand(0, 99), 2, '0', STR_PAD_LEFT);
        // regenerate emailLetters small random pick
        if (strlen($localClean) >= 2) {
            shuffle($chars);
            $emailLetters = $chars[0] . $chars[1];
        } else {
            $emailLetters = strtoupper(substr(Str::random(2), 0, 2));
        }
        $candidate = $partName . $roleFirst . $roleLast . $randDigits . $emailLetters;
    }

    return $candidate;
}

    // // Handle registration form submission
    // public function register(Request $request)
    // {
    //     // Validation
    //     $request->validate([
    //         'name' => 'required|string|max:150',
    //         'email' => 'required|email|unique:praveshjankari,email',
    //         'userid' => 'required|string|max:100|unique:praveshjankari,userid',
    //         'role_id' => 'required|exists:roles,id',
    //         'password' => 'required|string|min:6|confirmed',
    //     ]);

    //     // Insert into praveshjankari table
    //     $userId = DB::table('praveshjankari')->insertGetId([
    //         'name' => $request->name,
    //         'email' => $request->email,
    //         'userid' => $request->userid,
    //         'role_id' => $request->role_id,
    //         'password' => Hash::make($request->password),
    //         'created_at' => now(),
    //         'last_accessed' => now(),
    //     ]);

    //     // Redirect to login with success message
    //     return redirect()->route('login')->with('success', 'Registration successful! Please login.');
    // }

   public function register(Request $request)
{
    $request->validate([
        'name' => 'required|string|max:150',
        'email' => 'required|email|unique:praveshjankari,email',
        'role_id' => 'required|exists:roles,id',
        'password' => 'required|string|min:6|confirmed',
    ]);

    $role = DB::table('roles')->where('id', $request->role_id)->first();
    $roleName = $role ? $role->name : '';

    // Generate unique userid
    $userid = $this->generateUserId($request->name, $roleName, $request->email);

    // Insert into DB
    DB::table('praveshjankari')->insert([
        'name' => $request->name,
        'email' => $request->email,
        'userid' => $userid,
        'role_id' => $request->role_id,
        'password' => Hash::make($request->password),
        'created_at' => now(),
        'last_accessed' => now(),
    ]);

    // Redirect back to registration page with flash message
    return redirect()->back()->with('userid', $userid)->with('success', 'Account created successfully! Please note down your User ID and password to log in.');
}


}
