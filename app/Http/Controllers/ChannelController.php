<?php

namespace App\Http\Controllers;

use App\Models\Channel;
use Illuminate\Http\Request;

class ChannelController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    public function index()
    {
        return response()->json(['data'=> Channel::all()]);
    }

    public function create()
    {
        //
    }

    public function store(Request $request)
    {
        //
    }

    public function show(Channel $channel)
    {
        //
    }

    public function edit(Channel $channel)
    {
        //
    }

    public function update(Request $request, Channel $channel)
    {
        //
    }

    public function destroy(Channel $channel)
    {
        //
    }
}
