<?php namespace App\Http\Controllers;

use Hash;
use Config;
use Validator;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use GuzzleHttp;
use GuzzleHttp\Subscriber\Oauth\Oauth1;
use App\User;

class AuthController extends Controller {

    /**
     * Generate JSON Web Token.
     */
    protected function createToken($user)
    {
        $payload = [
            'sub' => $user->id,
            'iat' => time(),
            'exp' => time() + (2 * 7 * 24 * 60 * 60)
        ];
        return JWT::encode($payload, Config::get('app.token_secret'));
    }


    /**
     * Unlink provider.
     */
    public function unlink(Request $request, $provider)
    {
        $user = User::find($request['user']['sub']);

        if (!$user)
        {
            return response()->json(['message' => 'User not found']);
        }

        $user->$provider = '';
        $user->save();
        
        return response()->json(array('token' => $this->createToken($user)));
    }

    /**
     * Log in with Email and Password.
     */
    public function login(Request $request)
    {
        $email = $request->input('email');
        $password = $request->input('password');

        $user = User::where('email', '=', $email)->first();

        if (!$user)
        {
            return response()->json(['message' => 'Wrong email and/or password'], 401);
        }

        if (Hash::check($password, $user->password))
        {
            unset($user->password);

            return response()->json(['token' => $this->createToken($user)]);
        }
        else
        {
            return response()->json(['message' => 'Wrong email and/or password'], 401);
        }
    }

    /**
     * Create Email and Password Account.
     */
    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'firstName' => 'required',
            'lastName' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->messages()], 400);
        }

        $user = new User;
        $user->firstName = $request->input('firstName');
        $user->lastName = $request->input('lastName');
        $user->email = $request->input('email');
        $user->password = Hash::make($request->input('password'));
        $user->save();

        return response()->json(['token' => $this->createToken($user)]);
    }

    /**
     * Login with Facebook.
     */
    public function facebook(Request $request)
    {

        $client = new GuzzleHttp\Client();

        $params = [
            'code' => $request->input('code'),
            'client_id' => $request->input('clientId'),
            'redirect_uri' => $request->input('redirectUri'),
            'client_secret' => Config::get('app.facebook_secret')
        ];

        // Step 1. Exchange authorization code for access token.
        $accessTokenResponse = $client->request('GET', 'https://graph.facebook.com/v2.5/oauth/access_token', [
            'query' => $params
        ]);

        $accessToken = json_decode($accessTokenResponse->getBody(), true);

        // Step 2. Retrieve profile information about the current user.
        $fields = 'id,email,first_name,last_name,link,name,picture';
        $profileResponse = $client->request('GET', 'https://graph.facebook.com/v2.5/me', [
            'query' => [
                'access_token' => $accessToken['access_token'],
                'fields' => $fields
            ]
        ]);

     //   print '<pre>'; print_r($profileResponse);

        $profile = json_decode($profileResponse->getBody(), true);

        //print '<pre>'; print_r($profile); exit();

        // Step 3a. If user is already signed in then link accounts.
        if ($request->header('Authorization'))
        {
            $user = User::where('facebook', '=', $profile['id']);

            if ($user->first())
            {
                return response()->json(['message' => 'There is already a Facebook account that belongs to you'], 409);
            }

            $token = explode(' ', $request->header('Authorization'))[1];
            $payload = (array) JWT::decode($token, Config::get('app.token_secret'), array('HS256'));

            $user = User::find($payload['sub']);
            $user->facebook = $profile['id'];
            $user->displayName = $user->displayName ?: $profile['name'];
            $user->save();

            return response()->json(['token' => $this->createToken($user)]);
        }
        // Step 3b. Create a new user account or return an existing one.
        else
        {
            $user = User::where('email', '=', $profile['email']);

            /* If user is already present with the provided email then update facebook Id */
            if ($user->first())
            {
                $user = new User;
                $user->fb_profile_id = $profile['id'];              
                $user->save();

                // return response()->json(['token' => $this->createToken($user->first())]);
                return response()->json(['token' => $this->createToken($user)]);
            }

            $user = new User;
            $user->facebook = $profile['id'];              
            $name = explode(' ', $profile['name']);
            $user->firstName = $name[0];
            $user->lastName = $name[1];
            $user->email = $profile['email'];
            $user->save();

            return response()->json(['token' => $this->createToken($user)]);
        }
    }

    /**
     * Login with Google.
     */
    public function google(Request $request)
    {
        $client = new GuzzleHttp\Client();

        $params = [
            'code' => $request->input('code'),
            'client_id' => $request->input('clientId'),
            'client_secret' => Config::get('app.google_secret'),
            'redirect_uri' => $request->input('redirectUri'),
            'grant_type' => 'authorization_code',
        ];

        // Step 1. Exchange authorization code for access token.
        $accessTokenResponse = $client->request('POST', 'https://accounts.google.com/o/oauth2/token', [
            'form_params' => $params
        ]);
        $accessToken = json_decode($accessTokenResponse->getBody(), true);

        // Step 2. Retrieve profile information about the current user.
        $profileResponse = $client->request('GET', 'https://www.googleapis.com/plus/v1/people/me/openIdConnect', [
            'headers' => array('Authorization' => 'Bearer ' . $accessToken['access_token'])
        ]);

        $profile = json_decode($profileResponse->getBody(), true);

     
            $user = User::where('email', '=', $profile['email']);

            if ($user->first())
            {
                $user = new User;
                $user->google_plus_id = $profile['sub'];
                $user->firstName = $profile['given_name'];
                $user->lastName = $profile['family_name'];
                $user->profilePhoto = $profile['picture'];
                $user->save();

                return response()->json(['token' => $this->createToken($user->first())]);
            }
            else
            {
                $user = new User;
                $user->google_plus_id = $profile['sub'];
                $user->firstName = $profile['given_name'];
                $user->lastName = $profile['family_name'];
                $user->profilePhoto = $profile['picture'];
                
                $verified = 'no'; 
                if($profile['email_verified'])
                {
                    $verified = 'yes';
                }   

                $user->verified = $verified;
                $user->timezone = 'UTC';               
                $user->created_at = date('Y-m-d H:i:s');
                $user->source = 'webApp';
                $user->socialMedia = 'google';      

                $user->save();

            }

           
        return response()->json(['token' => $this->createToken($user)]);
    }
    

  
}

/*

    [kind] => plus#personOpenIdConnect
    [gender] => male
    [sub] => 101517499859388374805
    [name] => Devendra Verma
    [given_name] => Devendra
    [family_name] => Verma
    [profile] => https://plus.google.com/101517499859388374805
    [picture] => https://lh5.googleusercontent.com/-c3kXRgTWW8o/AAAAAAAAAAI/AAAAAAAAAOk/kFWSVTSYBMY/photo.jpg?sz=50
    [email] => verma.deven003@gmail.com
    [email_verified] => true
    [locale] => en-GB

*/