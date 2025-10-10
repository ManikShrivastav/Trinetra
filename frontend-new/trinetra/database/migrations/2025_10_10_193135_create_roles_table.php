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
        Schema::create('roles', function (Blueprint $table) {
            // Primary id
            $table->bigIncrements('id');

            // Compulsory timestamps: creation timestamp
            $table->timestamp('created_at')->useCurrent();

            // Compulsory last_accessed column
            $table->timestamp('last_accessed')->nullable()->useCurrent();

            // Role name
            $table->string('name', 100)->unique();

            // Optional: description
            $table->string('description')->nullable();

            // Indexes
            $table->index('name');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('roles');
    }
};
