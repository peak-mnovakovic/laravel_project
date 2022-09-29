<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use GuzzleHttp\Client;
use Laravel\Passport\Client as OClient; 
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;


use App\Models\User;


class PassportAuthController extends Controller
{
    //
    /**
     * Registration Req
     */
    public function register(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|min:4',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);
  
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
  
        $token = $user->createToken('Laravel-9-Passport-Auth')->accessToken;
  
        return response()->json(['token' => $token], 200);
    }
  
    /**
     * Login Req
     */
    public function login(Request $request)
    {
        $data = [
            'email' => $request->email,
            'password' => $request->password
        ];
  
        if (auth()->attempt($data)) {
            $token = auth()->user()->createToken('token')->accessToken;
            return response()->json(['token' => $token], 200);
        } else {
            return response()->json(['error' => 'Unauthorised'], 401);
        }
    }

    // public $successStatus = 200;
    // public function login() {
    //     $request = request();
    //     $url = $request->root();
    //     if (Auth::attempt(['email' => request('email'), 'password' => request('password')])) { 
    //         $oClient = OClient::where('password_client', 1)->first();
    //         return $this->getTokenAndRefreshToken($oClient, request('email'), request('password'),$url);
    //     } 
    //     else { 
    //         return response()->json(['error'=>'Unauthorised'], 401); 
    //     } 
    // }


    public function getTokenAndRefreshToken(OClient $oClient, $email, $password, $url) {
        $oClient = OClient::where('password_client', 1)->first();
        $request = request();
        $http = new Client;
       /* $response = $http->request('POST', $url.'/oauth/token', [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => $oClient->id,
                'client_secret' => $oClient->secret,
                'username' => $email,
                'password' => $password,
                'scope' => '',
            ],
        ]);*/

        $response = Http::asForm()->post($url.'/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $oClient->id,
            'client_secret' => $oClient->secret,
            //'redirect_uri' => 'http://third-party-app.com/callback',
            'code' => $request->code,
        ]);

        $result = json_decode((string) $response->getBody(), true);
        return response()->json($result, $this->successStatus);
    }

 
    public function userInfo() 
    {
 
     $user = auth()->user();
      
     return response()->json(['user' => $user], 200);
 
    }
}


