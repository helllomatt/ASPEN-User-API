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
    $auth = new OAuth2();
    $auth->validate();

    $response = new Response();
    if (!$auth->valid()) {
        $response->error('Unauthorized.');
    } else {
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
    }
});

return $app;
