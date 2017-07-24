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

    public function __construct($db) {
        $this->db = $db;
        $this->createServer();
    }

    /**
     * Handles the token request
     *
     * @return void
     */
    public function handleTokenRequest() {
        $this->server->handleTokenRequest(Request::createFromGlobals())->send();
    }

    /**
     * Validates a token
     *
     * @param  boolean $throw
     * @return void
     */
    public function validate($throw = false) {
        if (array_key_exists('user', $_SESSION)) $this->valid = true;
        elseif ($this->server->verifyResourceRequest(Request::createFromGlobals())) $this->valid = true;
    }

    /**
     * Returns the validity status of a token
     *
     * @return boolean
     */
    public function valid() {
        return $this->valid;
    }

    /**
     * Requires a valid token, this is a shortcut function.
     *
     * I don't know how I feel about die(). Leaning towards it being wrong.
     *
     * @return void
     */
    public function requireValidToken() {
        $this->validate();
        if (!$this->valid()) {
            $response = new Response();
            $response->error('Unauthorized.');
            die();
        }
    }

    /**
     * Returns the storage object
     *
     * @return Users\Pdo
     */
    public function getStorage() {
        return $this->storage;
    }

    /**
     * Returns the server object
     *
     * @return OAuth2\Server
     */
    public function getServer() {
        return $this->server;
    }

    /**
     * Gets the token information from the request
     *
     * @return array
     */
    public function getToken() {
        $token = $this->server->getAccessTokenData(Request::createFromGlobals());
        if ($token != null) return $token;
        return [
            'user_id' => $_SESSION['user']['id']
        ];
    }

    /**
     * Creates the OAuth2 Server
     *
     * @return void
     */
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

    /**
     * Returns the database connection string
     *
     * @return string
     */
    private function dsn() {
        return sprintf('mysql:dbname=%s;host%s;', $this->database_name, $this->database_host);
    }
}
