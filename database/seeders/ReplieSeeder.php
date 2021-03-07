<?php

namespace Database\Seeders;

use App\Models\Replie;
use Faker\Factory as Faker;
use Illuminate\Database\Seeder;

class ReplieSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Faker::create('fr_FR');
        for ($i = 0; $i <= 14; $i++) {
            $replie = new Replie();
            $replie->body = $faker->realText(80);
            $replie->user_id = mt_rand(1,2);
            $replie->thread_id = mt_rand(1,9);
            $replie->save();
        }
    }
}
