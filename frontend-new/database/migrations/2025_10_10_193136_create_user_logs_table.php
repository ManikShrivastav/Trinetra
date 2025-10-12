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
        Schema::create('user_logs', function (Blueprint $table) {
            // Primary id
            $table->bigIncrements('id');

            // Compulsory timestamps
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('last_accessed')->nullable()->useCurrent();

            // Log fields
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('ip', 45)->nullable(); // IPv6 safe
            $table->string('activity', 150); // e.g., "scan_started", "login_success"
            $table->text('details')->nullable(); // verbose details or JSON string

            // Foreign key to praveshjankari (users)
            $table->foreign('user_id')->references('id')->on('praveshjankari')->onDelete('set null');

            // Useful indexes
            $table->index('user_id');
            $table->index('activity');
            $table->index('created_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_logs');
    }
};
