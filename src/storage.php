<?php

namespace Users;

/**
 * This file is an extension off of the one supplied by bshaffer/oauth2-server-php
 *
 * I've modified it to use the built in DB engine, and to accomodate certain things
 * that I will be using. If need be in the future I wll use more things and fill in
 * the blanks here.
 *
 * Template file found here: https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/Pdo.php
 */

use ASPEN\Config;
use Double\DB;
use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

class Pdo implements AuthorizationCodeInterface, AccessTokenInterface,
    ClientCredentialsInterface, UserCredentialsInterface, RefreshTokenInterface,
    JwtBearerInterface, ScopeInterface, PublicKeyInterface, UserClaimsInterface,
    OpenIDAuthorizationCodeInterface {

    protected $db;
    protected $config;

    public function __construct($c, $config = array()) {
        if ($c instanceof DB) $this->db = $c;
        else $this->db = (new DB())->connect($c['host'], $c['username'], $c['password'], $c['database']);

        $this->config = array_merge([
            "client_table"                  => "auth_clients",
            "access_token_table"            => "user_access_tokens",
            "refresh_token_table"           => "user_refresh_tokens",
            "code_table"                    => "oauth_authorization_codes",
            "user_table"                    => "users",
            "user_permissions_rel_table"    => "user_permissions",
            "permissions_table"             => "permissions",
            "jwt_table"                     => "oauth_jwt",
            "jti_table"                     => "oauth_jti",
            "scope_table"                   => "oauth_scopes",
            "public_key_table"              => "oauth_public_keys",
        ], $config);
    }

    public function checkClientCredentials($client_id, $client_secret = null) {
        $query = $this->db->query("select")->from($this->config['client_table'])->where("client_id = :cid", [":cid" => $client_id])->execute();
        if ($query->failed() || $query->count() == 0) return false;

        $result = $query->fetch()[0];
        return $result['client_secret'] == $client_secret;
    }

    public function isPublicClient($client_id) {
        $query = $this->db->query("select")->from($this->config['client_table'])->where("client_id = :cid", [":cid" => $client_id])->execute();
        print_r($query->failed_because());
        if ($query->failed() || $query->count() == 0) return false;
        $client = $query->fetch()[0];
        return empty($client['client_secret']);
    }

    public function getClientDetails($client_id) {
        $query = $this->db->query("select")->from($this->config['client_table'])->where("client_id = :cid", [":cid" => $client_id])->execute();
        return $query->fetch();
    }

    public function checkRestrictedGrantType($client_id, $grant_type) {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);
            return in_array($grant_type, (array) $grant_types);
        }

        return true;
    }

    public function getAccessToken($access_token) {
        $query = $this->db->query("select")->from($this->config['access_token_table'])->where("access_token = :at", [":at" => $access_token])->execute();
        if ($query->failed() || $query->count() == 0) return false;

        $token = $query->fetch()[0];
        $token['expires'] = strtotime($token['expires']);
        return $token;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null) {
        $expires = date('Y-m-d H:i:s', $expires);
        if ($this->getAccessToken($access_token)) {
            $query = $this->db->query("update")->table($this->config['access_token_table'])
                ->set("client_id", $client_id)
                ->set("expires", $expires)
                ->set("user_id", $user_id)
                ->set("scope", $scope)
                ->where("access_token = :at", [":at" => $access_token])
                ->execute();
        } else {
            $query = $this->db->query("insert")->into($this->config['access_token_table'])
                ->columns(["access_token", "client_id", "user_id", "expires", "scope"])
                ->values([$access_token, $client_id, $user_id, $expires, $scope])
                ->execute();
        }

        return !$query->failed();
    }

    public function unsetAccessToken($access_token) {
        $query = $this->db->query("delete")->from($this->config['access_token_table'])->where("access_token = :at", [":at" => $access_token])->execute();
        return !$query->failed();
    }

    public function getAuthorizationCode($code) {
        $query = $this->db->query("select")->from($this->config['code_table'])
            ->where("authorization_code = :ac", [":ac" => $access_token])
            ->execute();

        if ($query->failed() || $query->count() == 0) return false;

        $code = $query->fetch()[0];
        $code['expires'] = strtotime($code['expires']);
        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null) {
        if (func_num_args() > 6) {
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }

        $expires = date('Y-m-d H:i:s', $expires);
        if ($this->getAuthorizationCode($code)) {
            $query = $this->db->query("update")->table($this->config['code_table'])
                ->set("client_id", $client_id)
                ->set("user_id", $user_id)
                ->set("redirect_uri", $redirect_uri)
                ->set("expires", $expires)
                ->set("scope", $scope)
                ->where("authorization_code = :ac", [":ac" => $code])
                ->execute();
        } else {
            $query = $this->db->query("insert")->into($this->config['code_table'])
                ->columns(["authorization_code", "client_id", "user_id", "redirect_uri", "expires", "scope"])
                ->values([$code, $client_id, $user_id, $redirect_uri, $expires, $scope])
                ->execute();
        }

        return !$query->failed();
    }

    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null) {
        if (func_num_args() > 6) {
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }

        $expires = date('Y-m-d H:i:s', $expires);
        if ($this->getAuthorizationCode($code)) {
            $query = $this->db->query("update")->table($this->config['code_table'])
                ->set("client_id", $client_id)
                ->set("user_id", $user_id)
                ->set("redirect_uri", $redirect_uri)
                ->set("expires", $expires)
                ->set("scope", $scope)
                ->set("id_token", $id_token)
                ->where("authorization_code = :ac", [":ac" => $code])
                ->execute();
        } else {
            $query = $this->db->query("insert")->into($this->config['code_table'])
                ->columns(["authorization_code", "client_id", "user_id", "redirect_uri", "expires", "scope", "id_token"])
                ->values([$code, $client_id, $user_id, $redirect_uri, $expires, $scope, $id_token])
                ->execute();
        }

        return !$query->failed();
    }

    public function expireAuthorizationCode($code) {
        $query = $this->db->query("delete")->from($this->config['code_table'])->where("authorization_code = :ac", [":ac" => $code])->execute();
        return !$query->failed();
    }

    public function checkUserCredentials($email, $password) {
        if ($user = $this->getUserByEmail($email))  return $this->checkPassword($user, $password);
        return false;
    }

    public function getUserDetails($id) {
        if (is_numeric($id)) return $this->getUser($id);
        else return $this->getUserByEmail($id);
    }

    public function getUserClaims($user_id, $claims) {
        if (!$userDetails = $this->getUserDetails($user_id)) return false;

        $claims = explode(' ', trim($claims));
        $userClaims = array();

        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    protected function getUserClaim($claim, $userDetails) {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);
        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }
        return $userClaims;
    }

    public function getRefreshToken($refresh_token) {
        $query = $this->db->query("select")->from($this->config['refresh_token_table'])->where("refresh_token = :rt", [":rt" => $refresh_token])->execute();
        if ($query->failed() || $query->count() == 0) return false;

        $token = $query->fetch()[0];
        $token['expires'] = strtotime($token['expires']);

        return $token;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null) {
        $expires = date('Y-m-d H:i:s', $expires);
        $query = $this->db->query("insert")->into($this->config['refresh_token_table'])
            ->columns(["refresh_token", "client_id", "user_id", "expires", "scope"])
            ->values([$refresh_token, $client_id, $user_id, $expires, $scope])
            ->execute();

        return !$query->failed();
    }

    public function unsetRefreshToken($refresh_token) {
        $query = $this->db->query("select")->from($this->config['refresh_token_table'])->where("refresh_token = :rt", [":rt" => $refresh_token])->execute();
        return $query->count() > 0;
    }

    protected function checkPassword($user, $password) {
        $authfunc = Config::get('user-auth-function');
        if ($authfunc != false) return $authfunc($user['password'], $password);
        else return password_verify($password, $user['password']);
    }

    public function getUser($id) {
        $query = $this->db->query("select")->from($this->config['user_table'])->where("id = :id", [":id" => $id])->execute();
        if ($query->failed() || $query->count() == 0) return false;
        $user = $query->fetch()[0];

        return array_merge(['user_id' => $user['id']], $user, $this->getPermissions($id));
    }

    public function getUserByEmail($email) {
        $query = $this->db->query("select")->from($this->config['user_table'])->where("email = :e", [":e" => $email])->execute();
        if ($query->failed() || $query->count() == 0) return false;
        $user = $query->fetch()[0];

        return array_merge(['user_id' => $user['id']], $user, $this->getPermissions($user['id']));
    }

    public function getPermissions($id) {
        $query = $this->db->query("select")->from($this->config['user_permissions_rel_table']." up")
            ->join("right", $this->config['permissions_table']." p", "up.permission_id = p.id")
            ->where("up.user_id = :uid", [":uid" => $id])
            ->execute();

        if ($query->failed() || $query->count() == 0) return [];
        $permissionInfo = $query->fetch();

        $permissions = [];
        foreach ($permissionInfo as $p) {
            $permissions[] = $p['permission'];
        }

        return ['permissions' => $permissions];
    }

    public function setUser($username, $password, $firstName = null, $lastName = null) {
        return false; // use something else. customize your life
    }

    public function scopeExists($scope) {
        return true;
    }

    public function getDefaultScope($client_id = null) {
        return '';
    }

    public function getClientKey($client_id, $subject) {
        $query = $this->db->query("select")
            ->columns(["public_key"])
            ->from($this->config['jwt_table'])
            ->where("client_id = :cid AND subject = :s", [":cid" => $client_id, ":s" => $subject])
            ->execute();

        if ($query->failed() || $query->count() == 0) return false;
        return $query->fetch();
    }

    public function getClientScope($client_id) {
        return null;
    }

    // just here so we don't get fined.
    public function getJti($client_id, $subject, $audience, $expiration, $jti) { return false; }
    public function setJti($client_id, $subject, $audience, $expiration, $jti) { return false; }
    public function getPublicKey($client_id = null) { return Config::get('keys')['public']; }
    public function getPrivateKey($client_id = null) { return Config::get('keys')['private']; }
    public function getEncryptionAlgorithm($client_id = null) { return 'RS256'; }
}
