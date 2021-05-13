<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
         //dd("store");
       $request->validate([
         'name' => 'required|string',
         "email" => 'required|string|unique:users|email',
         'password' => 'required|confirmed|string'
       ]);
       $user = User::create([
         'name' => $request->name,
         'email' => $request->email,
         'password' => Hash::make($request->password)
       ]);
       $token = $user->createToken('myapptoken')->plainTextToken;
       $response = [
         "user" => $user,
         "token" => $token
       ];
       return response($response, 201);
    }
    public function login(Request $request) {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response([
                'message' => 'Invalid cred'
            ], 401);
        }
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'token' => $token,
            'user' => $user
        ];
        return response($response, 201);
    }
    public function logout(Request $request) {
        auth()->user()->tokens()->delete();
        return response([
            'message' =>  'logged out'
        ], 200);
    }
}
