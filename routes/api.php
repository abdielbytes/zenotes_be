<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    Route::middleware('throttle:3,1')->group(function () {

        Route::prefix('auth')->group(function () {
            // Public routes
            Route::post('register', [AuthController::class, 'register']);
            Route::post('login', [AuthController::class, 'login']);

            // Authenticated routes
            Route::middleware('auth:api')->group(function () {
                Route::get('user', [AuthController::class, 'getUser']);
                Route::post('logout', [AuthController::class, 'logout']);
            });

        });
    });
});
