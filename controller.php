<?php

use ASPEN\API;
use ASPEN\Endpoint;
use ASPEN\Connector;
use ASPEN\Response;
use ASPEN\Config;
use Double\DB;
use Basically\CRUD;
use Basically\Errors;

use Users\OAuth2;
use Users\User;

$api = new API('User');
$api->version(1);

$api->add((new Endpoint([
        'to'     => 'users/login/',
        'method' => 'post'
    ]))->then(function (Response $response, Connector $c) {
        $db = $c->getDB('accounts');

        $username = CRUD::sanitize($c->getVariable('username'), ['string', 'required', 'xss', 'notags'],
            Errors::generate([
                'notstring' => "Invalid username.",
                'missing'   => "Please provide your username."
            ]));
        $password = CRUD::sanitize($c->getVariable('password'), ['string', 'required', 'xss', 'notags'],
            Errors::generate([
                'notstring' => "Invalid username.",
                'missing'   => "Please provide your password."
            ]));

        if (Config::get('user-class') != null) $uclass = Config::get('user-class');
        else $uclass = 'Users\User';
        $user = (new $uclass($db))->login($username, $password);

        $response->success();
    }));

$api->add((new Endpoint([
        'to'     => 'users/logout/',
        'method' => 'get'
    ]))->then(function (Response $response, Connector $c) {
        if (Config::get('user-class') != null) $uclass = Config::get('user-class');
        else $uclass = 'Users\User';
        $uclass::logout();

        $response->success();
    }));

$api->add((new Endpoint([
        'to' => 'users/authenticate/'
    ]))->then(function(Response $r, Connector $c) {
        $auth = new Oauth2($c->getDB('accounts'));
        $auth->handleTokenRequest();
    }));

$api->add((new Endpoint([
        'to' => 'users/validate-authentication/'
    ]))->then(function(Response $response, Connector $c) {
        $auth = new OAuth2($c->getDB('accounts'));
        $auth->validate();

        if ($auth->valid()) {
            $response->success();
        } else {
            $response->error('Unauthorized.');
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/register/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        try {
            $email = CRUD::sanitize($c->getVariable('email'), ['email', 'required'], Errors::generate([
                'bademail' => 'Invalid email.',
                'missing'  => 'Please provide an email address.'
            ]));
            $name = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full', 'notags', 'xss'], Errors::generate([
                'badname' => 'Invalid name',
                'missing' => 'Please provide your full name'
            ]));
            $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]], Errors::generate([
                'missing'  => 'Please provide a password',
                'tooshort' => 'Your password must be at least 4 characters long'
            ]));

            $db = $c->getDB('accounts');

            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';

            $id = $uclass::register($db, $email, $name, $password);
            $response->add('id', $id);
            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/activate/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        try {
            $code = CRUD::sanitize($c->getVariable('code'), ['required', 'string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required'],
                Errors::generateForAll('Invalid code.'));
            $email = CRUD::sanitize($c->getVariable('email'), ['required', 'email'], Errors::generate([
                'bademail' => 'Invalid email.',
                'missing'  => 'Failed to activate, missing a requirement.'
            ]));

            $db = $c->getDB('accounts');
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $user = (new $uclass($db))->getByEmail($email);

            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $uclass::activate($db, $user, $email, $code);
            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/reset-password-request/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        try {
            $email = CRUD::sanitize($c->getVariable('email'), ['required', 'email'], Errors::generate([
                'missing'  => 'Please provide your email address',
                'bademail' => 'Invalid email address'
            ]));

            $db = $c->getDB('accounts');
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $user = (new $uclass($db))->getByEmail($email);

            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $uclass::resetPasswordRequest($db, $user);

            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/reset-password/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        try {
            $code = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required'],
                Errors::generateForAll('Invalid code.'));
            $email = CRUD::sanitize($c->getVariable('email'), ['required', 'email'], Errors::generate([
                'missing'  => 'Please provide your email address',
                'bademail' => 'Invalid email address'
            ]));
            $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]], Errors::generate([
                'missing'  => 'Please provide a password',
                'tooshort' => 'Your password must be at least 4 characters long'
            ]));

            $db = $c->getDB('accounts');
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $user = (new $uclass($db))->getByEmail($email);

            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';
            $uclass::resetPassword($db, $user, $password, $code);
            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/update/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            try {
                $email = CRUD::sanitize($c->getVariable('email'), ['required', 'email'], Errors::generate([
                    'missing'  => 'Please provide your email address',
                    'bademail' => 'Invalid email address'
                ]));
                $name = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full', 'notags', 'xss'], Errors::generate([
                    'badname' => 'Invalid name',
                    'missing' => 'Please provide your full name'
                ]));

                $db   = $c->getDB('accounts');
                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $user = (new $uclass($db))->getSelf();

                $reactivate = false;
                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $uclass::update($db, $user, $reactivate, $email, $name);
                $response->add('reactivate', $reactivate);
                $response->success();
            } catch(Exception $e) {
                $response->error($e->getMessage());
            }
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/change-password/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            try {
                $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]], Errors::generate([
                    'missing'  => 'Please provide a password',
                    'tooshort' => 'Your password must be at least 4 characters long'
                ]));

                $db   = $c->getDB('accounts');
                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $user = (new $uclass($db))->getSelf();

                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $uclass::changePassword($db, $user, $password);
                $response->success();
            } catch(Exception $e) {
                $response->error($e->getMessage());
            }
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/delete/',
        'method' => 'post'
    ]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            try {
                $email = CRUD::sanitize($c->getVariable('email'), ['required', 'email'], Errors::generate([
                    'missing'  => 'Please provide your email address',
                    'bademail' => 'Invalid email address'
                ]));
                $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]], Errors::generate([
                    'missing'  => 'Please provide a password',
                    'tooshort' => 'Your password must be at least 4 characters long'
                ]));

                $db   = $c->getDB('accounts');
                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $user = (new $uclass($db))->getSelf();

                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $uclass::delete($db, $user, $email, $password);
                $response->success();
            } catch(Exception $e) {
                $response->error($e->getMessage());
            }
        }
    }));

$api->add((new Endpoint([
        'to'     => 'users/self/',
        'method' => 'get'
    ]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            try {
                $userId = $auth->getToken()['user_id'];

                if (Config::get('user-class') != null) $uclass = Config::get('user-class');
                else $uclass = 'Users\User';
                $user = new $uclass($c->getDB('accounts'));
                $user->getById($userId);

                $info = $user->info();
                unset($info['password']);
                unset($info['activationcode']);

                $response->add('user', $info);
                $response->success();
            } catch(Exception $e) {
                $response->error($e->getMessage());
            }
        }
    }));

$api->add((new Endpoint([
    'to'     => 'users/add-permission',
    'method' => 'post'
]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';

            $user = (new $uclass($c->getDB('accounts')))->getById($auth->getToken()['user_id']);
            if (!$user->hasPermission('give-permissions')) {
                $response->error('You don\'t have permission to give users permissions.');
            } else {
                try {
                    $user_id = CRUD::sanitize($c->getVariable('user_id'), ['required'], Errors::generate([
                        'missing' => 'Please provide a user ID'
                    ]));

                    if ($user_id == $user->info()['id'] && !$user->hasPermission('give-self-permissions')) {
                        throw new UserException('You don\'t have permission to give yourself permissions.');
                    }

                    $perm = CRUD::sanitize($c->getVariable('name'), ['string', 'required'], Errors::generate([
                        'missing'   => 'Please provide a permission to add',
                        'notstring' => 'Invalid permission'
                    ]));

                    $to_user = (new $uclass($c->getDB('accounts')))->getById($user_id);

                    $response->add('permission_added', $to_user->addPermission($perm));
                    $response->success();
                } catch(Exception $e) {
                    $response->error($e->getMessage());
                }
            }
        }
    }));

$api->add((new Endpoint([
    'to'     => 'users/remove-permission',
    'method' => 'post'
]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';

            $user = (new $uclass($c->getDB('accounts')))->getById($auth->getToken()['user_id']);
            if (!$user->hasPermission('take-permissions')) {
                $response->error('You don\'t have permission to remove users permissions.');
            } else {
                try {
                    $user_id = CRUD::sanitize($c->getVariable('user_id'), ['required'], Errors::generate([
                        'missing' => 'Please provide a user ID'
                    ]));
                    $perm = CRUD::sanitize($c->getVariable('name'), ['string', 'required'], Errors::generate([
                        'missing'   => 'Please provide a permission to add',
                        'notstring' => 'Invalid permission'
                    ]));

                    $to_user = (new $uclass($c->getDB('accounts')))->getById($user_id);

                    $response->add('permission_removed', $to_user->removePermission($perm));
                    $response->success();
                } catch(Exception $e) {
                    $response->error($e->getMessage());
                }
            }
        }
    }));

$api->add((new Endpoint([
    'to'     => 'users/permissions/create',
    'method' => 'post'
]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';

            $user = (new $uclass($c->getDB('accounts')))->getById($auth->getToken()['user_id']);
            if (!$user->hasPermission('create-permissions')) {
                $response->error('You don\'t have permission to create permissions.');
            } else {
                try {
                    $perm = CRUD::sanitize($c->getVariable('name'), ['string', 'required'], Errors::generate([
                        'missing'   => 'Please provide a permission to add',
                        'notstring' => 'Invalid permission'
                    ]));

                    $permissions = new Users\Permissions($c->getDB('accounts'));
                    $response->add('permission_id', $permissions->create($perm));
                    $response->success();
                } catch(Exception $e) {
                    $response->error($e->getMessage());
                }
            }
        }
    }));

$api->add((new Endpoint([
    'to'     => 'users/permissions/delete',
    'method' => 'post'
]))->then(function(Response $response, Connector $c) {
        $auth = new Users\OAuth2($c->getDB('accounts'));
        $auth->validate();

        if (!$auth->valid()) {
            $response->error('Unauthorized.');
        } else {
            if (Config::get('user-class') != null) $uclass = Config::get('user-class');
            else $uclass = 'Users\User';

            $user = (new $uclass($c->getDB('accounts')))->getById($auth->getToken()['user_id']);
            if (!$user->hasPermission('delete-permissions')) {
                $response->error('You don\'t have permission to delete permissions.');
            } else {
                try {
                    $perm = CRUD::sanitize($c->getVariable('name'), ['string', 'required'], Errors::generate([
                        'missing'   => 'Please provide a permission to add',
                        'notstring' => 'Invalid permission'
                    ]));

                    $permissions = new Users\Permissions($c->getDB('accounts'));
                    $response->add('deleted', $permissions->delete($perm));
                    $response->success();
                } catch(Exception $e) {
                    $response->error($e->getMessage());
                }
            }
        }
    }));

return $api;
