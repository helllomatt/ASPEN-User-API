<?php

use ASPEN\Connector;
use ASPEN\Response;

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

return $app;
