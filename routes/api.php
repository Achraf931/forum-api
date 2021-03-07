<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ChannelController;
use App\Http\Controllers\ThreadController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
Route::post('/auth/login', [AuthController::class, 'login'])->name('login');
Route::post('/auth/register', [AuthController::class, 'register'])->name('register');
Route::post('/auth/me', [AuthController::class, 'me'])->name('user');
Route::get('/channels', [ChannelController::class, 'index'])->name('channels');
Route::get('/threads', [ThreadController::class, 'index'])->name('threads');
Route::post('/threads', [ThreadController::class, 'store'])->name('addThread');
Route::get('/threads/{id}', [ThreadController::class, 'show'])->name('showThread');
Route::delete('/threads/{id}', [ThreadController::class, 'destroy'])->name('destroyThread');
Route::put('/threads/{id}', [ThreadController::class, 'update'])->name('updateThread');
