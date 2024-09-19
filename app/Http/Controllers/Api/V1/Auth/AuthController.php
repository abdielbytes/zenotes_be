<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\DB;


//use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // Register new user
    public function register(Request $request)
    {
        // Validate the request data
        $attributes = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'referral_code' => 'nullable|string'
        ]);

        // Validate email domain
        $email = $request->email;
        $emailParts = explode('@', $email);
        $domain = array_pop($emailParts);

        if (!$this->isValidDomain($domain)) {
            return response()->json([
                'status_code' => 400,
                'message' => 'Invalid email domain.',
            ], 400);
        }

        try {
            DB::beginTransaction();

            // Handle referral logic if applicable
            $referralUser = null;
            if (!empty($request->referral_code)) {
                $referralUser = User::where('invite_link', $request->referral_code)->first();
                if ($referralUser) {
                    // Logic for handling referral actions (e.g., increment referral count, send an email)
                    // You can customize this logic based on your needs.
                }
            }

            // Create the new user
            $user = User::create([
                'name' =>$request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'invite_link' => $this->getInviteCode(),
                'ref_by' => $referralUser->id ?? null,  // Set ref_by to null if no referral user
            ]);

            DB::commit();

            // Generate a JWT token for the registered user
            $token = JWTAuth::fromUser($user);

            return response()->json([
                'status_code' => 201,
                'message' => 'User registered successfully.',
                'token' => $token,
                'user' => $user,
            ], 201);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'status_code' => 500,
                'message' => 'Registration failed.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    // Login user and return JWT token
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'Could not create token'], 500);
        }

        return response()->json(['token' => $token]);
    }

    // Get authenticated user
    public function getUser()
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['error' => 'User not found'], 404);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'Token is invalid'], 400);
        }

        return response()->json(['user' => $user]);
    }

    // Logout user (invalidate token)
    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'User successfully logged out']);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to logout, please try again'], 500);
        }
    }


    /**
     * Validate the domain of the email.
     */
    private function isValidDomain($domain)
    {
        // Check if the domain matches a valid format
        $isValidFormat = preg_match('/^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$/', $domain);

        // Check if the domain has valid DNS records
        if (!$isValidFormat || (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A'))) {
            return false;
        }

        return true;
    }

    /**
     * Generate a unique invite code for the user.
     */
    private function getInviteCode()
    {
        return bin2hex(random_bytes(5)); // Example of generating a random code

        /*
        $length = 8;
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        do {
            $code = substr(str_shuffle($characters), 0, $length);
        } while (User::where('invite_link', $code)->exists());

        return $code;
    */
    }
}
