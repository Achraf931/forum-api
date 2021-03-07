<?php

namespace Database\Seeders;

use App\Models\Thread;
use Faker\Factory as Faker;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class ThreadsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Faker::create('fr_FR');
        for ($i = 0; $i <= 9; $i++) {
            $thread = new Thread();
            $thread->title = $faker->catchPhrase;
            $thread->slug = Str::slug($thread->title);
            $thread->body = $faker->realText(100);
            $thread->user_id = mt_rand(1,2);
            $thread->channel_id = mt_rand(1,6);
            $thread->save();
        }
    }
}
