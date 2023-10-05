<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('guest')->except([
            'logout','dashboard'
        ]);
    }
    //from register
    public function register()
    {
        return view('auth.register');
    }
    //store register
    public function store(Request $request, User $user, Auth $auth)
    {
        $request->validate([
            'name'  =>  'required|string|max:250',
            'email' =>  'required|email|max:250|unique:users,email',
            'password'  =>  'required|min:8',
        ]);

        $user::create([
            'name'  =>  $request->name,
            'email' =>  $request->email,
            'password'  =>  Hash::make($request->password)
        ]);

        $scredential = $request->only('email', 'password');
        $auth::attempt($scredential);
        $request->session()->regenerate();
        return redirect()->route('auth.dashboard')
        ->withSuccess('Anda telah registrasi dan login!');
    }
    //from login
    public function login()
    {
        return view('auth.login');
    }
    //authentication
    public function authentication(Request $request, Auth $auth)
    {
        $request->validate([
            'email' =>  'required|email',
            'password'  =>  'required'
        ]);
        $scredential = $request->only('email', 'password');
            if($auth::attempt($scredential));
            {
                $request->session()->regenerate();
                return redirect()->route('auth.dashboard');
            }
            return back()->withErrors([
                'email' => 'Email tidak ditemukan',
            ])->onlyInput('email');
    }
    //dashboard
    public function dashboard()
    {
        if(Auth::check())
        {
            return view('auth.dashboard');
        }
        return redirect()->route('auth.login');
    }
    //logout
    public function logout(Request $request, Auth $auth,)
    {
        $auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('auth.login');
    }
}