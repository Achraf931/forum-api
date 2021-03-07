<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Faker\Factory as Faker;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Faker::create('fr_FR');
        for ($i = 0; $i < 2; $i++) {
            $user = new User();
            $user->name = $faker->name;
            $user->email = $faker->email;
            $user->password = Hash::make("test");
            $user->save();
        }
    }
}
