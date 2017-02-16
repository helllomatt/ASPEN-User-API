<?php

use ASPEN\Connector;
use ASPEN\Response;
use ASPEN\Config;
use Double\DB;
use Basically\CRUD;

use Users\OAuth2;

$app = new ASPEN\App('OAuth2');
$app->version(1);

function getUserDB() {
    return (new DB())->connect(Config::get("db")['host'], Config::get("db")['username'], Config::get("db")['password'], Config::get("db")['dbname']);
}

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
        $email      = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
        $name       = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full', 'notags', 'xss']);
        $password   = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

        $db = Users\getUserDB();

        $id = Users\User::register($response, $db, $email, $name, $password);
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
        $code   = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
        $email  = CRUD::sanitize($c->getVariable('email'), ['email']);

        $db = Users\getUserDB();
        $user = (new Users\User($db))->getByEmail($email);

        Users\User::activate($db, $user, $email, $code)
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

        $db = getUserDB();
        $user = (new Users\User($db))->getByEmail($email);

        Users\User::resetPasswordRequest($db, $user);

        $response->success();
    } catch(Exception $e) {
        $response->error($e->getMessage());
    }
});

$app->get('users/reset-password', function(Connector $c) {
    if (!$c->usingMethod('POST')) return false;

    $response = new Response();
    try {
        $code     = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
        $email    = CRUD::sanitize($c->getVariable('email'), ['email']);
        $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

        $db = getUserDb();
        $user = (new Users\User($db))->getByEmail($email);

        Users\User::resetPassword($db, $user, $password, $code);
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
            $email = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
            $name  = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full']);

            $db   = getUserDB();
            $user = (new User($db))->getSelf();

            $reactivate = false;
            Users\User::update($db, $user, $reactivate, $email, $name);
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
            $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

            $db   = getUserDB();
            $user = (new User($db))->getSelf();

            Users\User::changePassword($db, $user, $password);
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
            $email    = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
            $password = CRUD::sanitize($c->getVariable('password'), ['string', 'required']);

            $db   = getUserDB();
            $user = (new Users\User($db))->getSelf();

            Users\User::delete($db, $user, $email, $password);
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
//         $permissions->create('add-users');
//         $user->getSelf()->addPermission('get-user-identities');
//         if ($user->getSelf()->hasPermission('add-users')) {
//             $response->add('can', 'add-users');
//         } else {
//             $response->add('cannot', 'add-users');
//         }
//
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
