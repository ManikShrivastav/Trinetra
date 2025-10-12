<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class RolesTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        //
        $roles = [
            ['name' => 'admin', 'description' => 'Administrator'],
            ['name' => 'officer', 'description' => 'Security Officer'],
            ['name' => 'analyst', 'description' => 'Security Analyst'],
            ['name' => 'helper', 'description' => 'Technical Helper'],
            ['name' => 'vice_head', 'description' => 'Vice Head'],
            ['name' => 'intern', 'description' => 'Intern'],
        ];

        foreach ($roles as $r) {
            DB::table('roles')->insert([
                'name' => $r['name'],
                'description' => $r['description'],
                'created_at' => now(),
                'last_accessed' => now(),
            ]);
        }
    }
}
