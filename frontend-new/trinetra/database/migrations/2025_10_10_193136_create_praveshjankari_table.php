<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('praveshjankari', function (Blueprint $table) {
            // Primary id
            $table->bigIncrements('id');

            // Compulsory timestamps
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('last_accessed')->nullable()->useCurrent();

            // Unique/obfuscation fields
            $table->string('userid', 100)->unique(); // login id (not raw numeric)
            $table->string('email', 150)->unique();
            $table->string('name', 150);

            // Role as FK to roles.id
            $table->unsignedBigInteger('role_id')->nullable();
            $table->foreign('role_id')->references('id')->on('roles')->onDelete('set null');

            // Password (hashed) and optional metadata
            $table->string('password', 255);
            $table->string('phone', 30)->nullable();
            $table->boolean('is_active')->default(true);

            // Optional: last_login_at separate from last_accessed
            $table->timestamp('last_login_at')->nullable();

            // Indexes
            $table->index('userid');
            $table->index('email');
            $table->index('role_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('praveshjankari');
    }
};
