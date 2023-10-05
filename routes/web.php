<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PagesController;
use App\Http\Controllers\CastController;
use App\Http\Controllers\GenreController;
use App\Http\Controllers\AuthController;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

// Route::get('/index', function () {
    // return view('index');
// })->name('index');

// Route::get('/form', function () {
//     return view('form');
// })->name('form');

// Route::get('/welcome1', function () {
//     return view('welcome1');
//  })->name('welcome1');

Route::controller(AuthController::class)->group(function(){
    Route::get('/registration', 'register')->name('auth.register');
    Route::post('/store', 'store')->name('auth.store');
    Route::get('/login', 'login')->name('auth.login');
    Route::post('/auth', 'authentication')->name('auth.authentication');
    Route::get('/dashboard', 'dashboard')->name('auth.dashboard');
    Route::post('/logout', 'logout')->name('auth.logout');
});

Route::get('/index',[PagesController::class,'index'])->name('index');
Route::get('/form',[PagesController::class,'form'])->name('form');
Route::get('/welcome1',[PagesController::class,'welcome1'])->name('welcome1');

route::get('/master',function (){
    return view('template.master');
});
Route::resource('/cast',CastController::class,)->middleware('auth');
Route::resource('/genre',GenreController::class,)->middleware('auth');