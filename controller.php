<?php

use ASPEN\API;
use ASPEN\Endpoint;
use ASPEN\Connector;
use ASPEN\Response;
use ASPEN\Config;
use Double\DB;
use Basically\CRUD;

use Users\OAuth2;
use Users\User;

$api = new API('User');
$api->version(1);

$api->add((new Endpoint([
        'to'     => 'users/login/',
        'method' => 'post'
    ]))->then(function (Response $response, Connector $c) {
        $db = $c->getDB('accounts');

        $username = CRUD::sanitize($c->getVariable('username'), ['string', 'required', 'xss', 'notags']);
        $password = CRUD::sanitize($c->getVariable('password'), ['string', 'required', 'xss', 'notags']);

        $user = (new User($db))->login($username, $password);

        $response->success();
    }));

$api->add((new Endpoint([
        'to'     => 'users/logout/',
        'method' => 'get'
    ]))->then(function (Response $response, Connector $c) {
        User::logout();

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
            $email      = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
            $name       = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full', 'notags', 'xss']);
            $password   = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

            $db = $c->getDB('accounts');

            $id = User::register($db, $email, $name, $password);
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
            $code   = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
            $email  = CRUD::sanitize($c->getVariable('email'), ['email']);

            $db = $c->getDB('accounts');
            $user = (new User($db))->getByEmail($email);

            User::activate($db, $user, $email, $code);
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
            $email = CRUD::sanitize($c->getVariable('email'), ['email']);

            $db = $c->getDB('accounts');
            $user = (new User($db))->getByEmail($email);

            User::resetPasswordRequest($db, $user);

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
            $code     = CRUD::sanitize($c->getVariable('code'), ['string', 'match' => 'a-z0-9', 'strlen' => ['short' => 128, 'long' => 128], 'required']);
            $email    = CRUD::sanitize($c->getVariable('email'), ['email']);
            $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

            $db = $c->getDB('accounts');
            $user = (new User($db))->getByEmail($email);

            User::resetPassword($db, $user, $password, $code);
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
                $email = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
                $name  = CRUD::sanitize($c->getVariable('name'), ['name', 'required-full']);

                $db   = $c->getDB('accounts');
                $user = (new User($db))->getSelf();

                $reactivate = false;
                User::update($db, $user, $reactivate, $email, $name);
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
                $password = CRUD::sanitize($c->getVariable('password'), ['password', 'required', 'string', 'strlen' => ['short' => 4]]);

                $db   = $c->getDB('accounts');
                $user = (new User($db))->getSelf();

                User::changePassword($db, $user, $password);
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
                $email    = CRUD::sanitize($c->getVariable('email'), ['email', 'required']);
                $password = CRUD::sanitize($c->getVariable('password'), ['string', 'required']);

                $db   = $c->getDB('accounts');
                $user = (new User($db))->getSelf();

                User::delete($db, $user, $email, $password);
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

                $db = $c->getDB('accounts');
                $query = $db->query('select')->from('users')->where('id = :id', [':id' => $userId])->execute();
                if ($query->failed()) throw new Exception('failed to get user');
                if ($query->count() == 0) throw new Exception('you do not exist.');
                $user = $query->fetch()[0];
                unset($user['password']);
                unset($user['activationcode']);

                $response->add('user', $user);
                $response->success();
            } catch(Exception $e) {
                $response->error($e->getMessage());
            }
        }
    }));

return $api;
