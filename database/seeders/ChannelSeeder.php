<?php

namespace Database\Seeders;

use Faker\Factory as Faker;
use Illuminate\Database\Seeder;
use App\Models\Channel;
use Illuminate\Support\Str;

class ChannelSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Faker::create('fr_FR');
        for ($i = 0; $i <= 5; $i++) {
            $channel = new Channel();
            $channel->title = $faker->catchPhrase;
            $channel->slug = Str::slug($channel->title);
            $channel->description = $faker->text(100);
            $channel->save();
        }
    }
}
