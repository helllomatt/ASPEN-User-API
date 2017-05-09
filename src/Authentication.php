<?php

namespace Users;

use ASPEN\Config;
use ASPEN\Response;
use Double\DB;

use OAuth2\Request;
use OAuth2\Autoloader;
use OAuth2\Server;
use OAuth2\GrantType\UserCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\AuthorizationCode;

class OAuth2 {
    private $server     = null;
    private $storage    = null;
    private $db         = null;
    private $valid = false;

    public function __construct() {
        $database_name = Config::get("db")['dbname'];
        $database_host = Config::get("db")['host'];
        $database_user = Config::get("db")['username'];
        $database_pass = Config::get("db")['password'];

        $this->db = (new DB())->connect($database_host, $database_user, $database_pass, $database_name);
        $this->createServer();
    }

    public function handleTokenRequest() {
        $this->server->handleTokenRequest(Request::createFromGlobals())->send();
    }

    public function validate($throw = false) {
        if ($this->server->verifyResourceRequest(Request::createFromGlobals())) $this->valid = true;
    }

    public function valid() {
        return $this->valid;
    }

    public function requireValidToken() {
        $this->validate();
        if (!$this->valid()) {
            $response = new Response();
            $response->error('Unauthorized.');
            die();
        }
    }

    public function getStorage() {
        return $this->storage;
    }

    public function getServer() {
        return $this->server;
    }

    public function getToken() {
        return $this->server->getAccessTokenData(Request::createFromGlobals());
    }

    public function getUser() {
        $token = $this->getToken();
        $query = $this->db->query("select")
            ->columns(["email", "firstname", "lastname"])
            ->from("users")
            ->where("id = :uid", [":uid" => $token['user_id']])
            ->execute();

        if ($query->failed() || $query->count() == 0) return [];
        return array_merge($query->fetch()[0], $this->storage->getPermissions($token['user_id']));
    }

    public function requirePermission($permission = '') {
        $this->requireValidToken();
        $user = $this->getUser();
        if (!$user || !in_array($permission, $user['permissions'])) {
            $response = new Response();
            $response->error('Invalid permission');
            die();
        }

        return true;
    }

    private function createServer() {
        Autoloader::register();

        $storage = new Pdo($this->db, [
            'user_table' => 'users'
        ]);

        $server = new Server($storage);

        $server->addGrantType(new UserCredentials($storage));
        $server->addGrantType(new RefreshToken($storage, ["always_issue_new_refresh_token" => true]));
        $server->addGrantType(new AuthorizationCode($storage));

        $this->server   = $server;
        $this->storage  = $storage;
    }

    private function dsn() {
        return sprintf('mysql:dbname=%s;host%s;', $this->database_name, $this->database_host);
    }
}
