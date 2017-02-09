<?php

use ASPEN\Connector;
use ASPEN\Response;

$app = new ASPEN\App('OAuth2');
$app->version(1);

$app->get('oauth2/token/', function() {
    $auth = new Users\Auth();
    $auth->handleTokenRequest();
});

$app->get('oauth2/validate/', function() {
    $auth = new Users\Auth();
    $auth->validate();

    $response = new Response();
    if ($auth->valid()) {
        $response->success();
    } else {
        $response->error('Unauthorized.');
    }
});

$app->get('identity/', function() {
    $auth = new Users\Auth();
    $auth->requireValidToken();

    $response = new Response();
    $response->add('identity', $auth->getUser());
    $response->success();
});

return $app;
