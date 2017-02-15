<?php

use ASPEN\Connector;
use ASPEN\Response;
use ASPEN\Config;
use Double\DB;
use Basically\CRUD;

use Users\OAuth2;

$app = new ASPEN\App('OAuth2');
$app->version(1);

$app->get('users/authenticate/', function() {
    $auth = new Users\OAuth2();
    $auth->handleTokenRequest();
});

$app->get('users/validate-authentication/', function() {
    $auth = new Users\OAuth2();
    $auth->validate();

    $response = new Response();
    if ($auth->valid()) {
        $response->success();
    } else {
        $response->error('Unauthorized.');
    }
});

$app->get('users/register/', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;

    $response = new Response();
    try {
        $name = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full', 'notags', 'xss']);
        $data = CRUD::compile([
            'email'             => CRUD::sanitize($c->getVariable('email'), ['email', 'required']),
            'password'          => CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]),
            'firstname'         => $name['first'],
            'lastname'          => $name['last'],
            'created'           => ['now()'],
            'activated'         => false,
            'activationcode'    => hash('SHA512', mt_rand(100000, 99999).time().$_SERVER['REMOTE_ADDR'])
        ]);

        $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
        $query = $db->query('select')->from('users')->where('email = :e', [':e' => $data['values'][0]])->execute();
        if ($query->failed()) throw new Exception('failed to check email');
        if ($query->count() > 0) throw new Exception('email already registered');

        $id = CRUD::insert($db, 'users', $data);

        $response->add('id', $id);
        $response->success();
    } catch(Exception $e) {
        $response->error($e->getMessage());
    }
});

$app->get('users/activate/', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;

    $response = new Response();
    try {
        $code = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
        $email = CRUD::sanitize($c->getVariable('email'), ['email']);

        $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
        $query = $db->query('select')->from('users')->where('email = :e && activationcode = :a', [':e' => $email, ':a' => $code])->execute();
        if ($query->failed()) throw new Exception('failed to check code');
        if ($query->count() != 1) throw new Exception('user not found');

        CRUD::update($db, 'users', CRUD::compile([
            'activated' => true
        ]), [
            'expression' => 'email = :e && activationcode = :a',
            'data'       => [':e' => $email, ':a' => $code]
        ]);

        $response->success();
    } catch(Exception $e) {
        $response->error($e->getMessage());
    }
});

$app->get('users/reset-password-request', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;

    $response = new Response();
    try {
        $email = CRUD::sanitize($c->getVariable('email'), ['email']);

        $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
        $query = $db->query('select')->from('users')->where('email = :e', [':e' => $email])->execute();
        if ($query->failed()) throw new Exception('failed to get user');
        if ($query->count() == 0) throw new Exception('user with that email not found');
        $user = $query->fetch()[0];

        $query = $db->query('select')->from('users_password_reset_requests')->where('user_id = :uid && expires > now()', [':uid' => $user['id']])->execute();
        if ($query->failed()) throw new Exception('failed to check for an existing request');
        if ($query->count() > 0) throw new Exception('request already sent.');

        CRUD::insert($db, 'users_password_reset_requests', CRUD::compile([
            'user_id'   => $user['id'],
            'code'      => hash('SHA512', mt_rand(100000, 99999).time().$_SERVER['REMOTE_ADDR']),
            'expires'   => date('Y-m-d h:i:S', strtotime('+1 day'))
        ]));

        $response->success();
    } catch(Exception $e) {
        $response->error($e->getMessage());
    }
});

$app->get('users/reset-password', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;

    $response = new Response();
    try {
        $code = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
        $email = CRUD::sanitize($c->getVariable('email'), ['email']);

        $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
        $query = $db->query('select')->columns(['u.id as user_id', 'uprr.id as request_id'])->from('users_password_reset_requests uprr')
            ->join('right', 'users u', 'uprr.user_id = u.id')
            ->where('uprr.code = :c && u.email = :e', [':c' => $code, ':e' => $email])
            ->execute();
        if ($query->failed()) throw new Exception('failed to get user');
        if ($query->count() == 0) throw new Exception('no reset password request found');
        $reset = $query->fetch()[0];

        CRUD::update($db, 'users', CRUD::compile([
            'password' => CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]),
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $reset['user_id']]
        ]);

        CRUD::delete($db, 'users_password_reset_requests', [
            'expression'    => 'id = :id',
            'data'          => [':id' => $reset['request_id']]
        ]);

        $response->success();
    } catch(Exception $e) {
        $response->error($e->getMessage());
    }
});

$app->get('users/update', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;
    $auth = new Users\OAuth2();
    $auth->validate();

    $response = new Response();
    if (!$auth->valid()) {
        $response->error('Unauthorized.');
    } else {
        try {
            $userId = $auth->getToken()['user_id'];

            $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
            $query = $db->query('select')->from('users')->where('id = :id', [':id' => $userId])->execute();
            if ($query->failed()) throw new Exception('failed to get user');
            if ($query->count() == 0) throw new Exception('you do not exist.');
            $user = $query->fetch()[0];

            $reactivate = false;
            $email = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
            if ($user['email'] != $email) $reactivate = true;

            $name = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full']);

            CRUD::update($db, 'users', CRUD::compile([
                'email'     => $email,
                'firstname' => $name['first'],
                'lastname'  => $name['last'],
                'activated' => $reactivate ? 3 : 1,
                'activationcode' => $reactivate ? hash('SHA512', mt_rand(100000, 99999).time().$_SERVER['REMOTE_ADDR']) : $user['activationcode']
            ]), [
                'expression'    => 'id = :id',
                'data'          => [':id' => $user['id']]
            ]);

            $response->add('reactivate', $reactivate);
            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }
});

$app->get('users/change-password', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;
    $auth = new Users\OAuth2();
    $auth->validate();

    $response = new Response();
    if (!$auth->valid()) {
        $response->error('Unauthorized.');
    } else {
        try {
            $userId = $auth->getToken()['user_id'];

            $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
            $query = $db->query('select')->from('users')->where('id = :id', [':id' => $userId])->execute();
            if ($query->failed()) throw new Exception('failed to get user');
            if ($query->count() == 0) throw new Exception('you do not exist.');
            $user = $query->fetch()[0];

            CRUD::update($db, 'users', CRUD::compile([
                'password' => CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]),
            ]), [
                'expression'    => 'id = :id',
                'data'          => [':id' => $user['id']]
            ]);

            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }
});

$app->get('users/delete', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;
    $auth = new Users\OAuth2();
    $auth->validate();

    $response = new Response();
    if (!$auth->valid()) {
        $response->error('Unauthorized.');
    } else {
        try {
            $userId = $auth->getToken()['user_id'];

            $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
            $query = $db->query('select')->from('users')->where('id = :id', [':id' => $userId])->execute();
            if ($query->failed()) throw new Exception('failed to get user');
            if ($query->count() == 0) throw new Exception('you do not exist.');
            $user = $query->fetch()[0];

            $email = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
            if ($email != $user['email']) {
                throw new Exception('invalid email');
            }

            $password = CRUD::sanitize($c->getVariable('password'), ['string', 'required']);
            if (!password_verify($password, $user['password'])) {
                throw new Exception('invalid password');
            }

            CRUD::delete($db, 'users', [
                'expression'    => 'id = :id',
                'data'          => [':id' => $user['id']]
            ]);

            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }
});

$app->get('users/self', function(Connector $c) {
    if (!$c->usingMethod('GET')) return false;
    $auth = new Users\OAuth2();
    $auth->validate();

    $response = new Response();
    if (!$auth->valid()) {
        $response->error('Unauthorized.');
    } else {
        try {
            $userId = $auth->getToken()['user_id'];

            $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
            $query = $db->query('select')->from('users')->where('id = :id', [':id' => $userId])->execute();
            if ($query->failed()) throw new Exception('failed to get user');
            if ($query->count() == 0) throw new Exception('you do not exist.');
            $user = $query->fetch()[0];
            unset($user['password']);

            $response->add('user', $user);
            $response->success();
        } catch(Exception $e) {
            $response->error($e->getMessage());
        }
    }
});

// $app->get('users/test', function() {
//     $db = (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
//     $user = new Users\User($db);
//
//     $response = new Response();
//     try {
//         $permissions = new Users\Permissions($db);
//
//         $response->add('permission to add user', $user->hasPermission('add-users'));
//         $response->add('permission to create blog posts', $user->hasPermission('create-blog-posts'));
//         $response->add('new permission', $permissions->create('some-permission'));
//         $user->addPermission('some-permission');
//         $user->removePermission('some-permission');
//         $permissions->delete('some-permission');
//         $response->add('permissions', $user->getPermissions(1));
//         $response->success();
//     } catch(Exception $e) {
//         $response->error($e->getMessage());
//     }
// });

return $app;
