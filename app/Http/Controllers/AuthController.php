<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails())
        {
            return response()->json(["errors" => $validator->errors()], 422);
        }

        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials))
        {
            return response()->json(['errors' => ['message' => 'Unauthorized']], 401);
        }

        $data = (object)[
            'name' => auth()->user()->name,
            'email'=> auth()->user()->email
        ];

        return response()->json(['data' => $data ,'meta' => $this->respondWithToken($token)]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required'
        ]);

        if ($validator->fails())
        {
            return response()->json(["errors" => $validator->errors()], 422);
        }

        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();

        $token = "";

        if ($user)
        {
            $credentials = request(['email', 'password']);

            if (!$token = auth()->attempt($credentials))
            {
                return response()->json(['errors' => ['message' => 'Unauthorized']], 401);
            }
        }

        $data = (object)[
            'name' => auth()->user()->name,
            'email'=> auth()->user()->email
        ];

        return response()->json(['data' => $data,'meta' => $this->respondWithToken($token)],201);
    }

    public function me(Request $request)
    {
        $data = (object)[
            'name' => auth()->user()->name,
            'email'=> auth()->user()->email
        ];

        return response()->json(['data' => $data]);

    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60 * 24
        ]);
    }
}
