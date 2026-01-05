<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Example migration for users table
 *
 * Run: php artisan make:migration create_users_table
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('username')->unique();
            $table->string('email')->unique();
            $table->string('password');
            $table->json('roles')->default('["user"]');
            $table->boolean('is_active')->default(true);
            $table->boolean('is_locked')->default(false);
            $table->timestamp('last_login_at')->nullable();
            $table->integer('failed_login_attempts')->default(0);
            $table->timestamp('locked_until')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index('username');
            $table->index('email');
            $table->index('is_active');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
