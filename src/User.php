<?php

namespace Users;

use Double\DB;
use Basically\CRUD;
use Exception;

class User {
    private $db;
    private $user;
    public function __construct(DB $db) {
        $this->db = $db;
    }

    public function info() {
        return $this->user;
    }

    public function login($username, $password) {
        $query = $this->db->query('select')->from('users')
            ->where('email = :e', [':e' => $username])
            ->execute();

        if ($query->failed()) throw new Exception('Failed to log in. Please try again later.');
        if ($query->count() == 0) throw new Exception('Invalid username or password.');
        $user = $query->fetch()[0];

        if (!password_verify($password, $user['password'])) {
            throw new Exception('Invalid username or password.');
        }

        $_SESSION['user'] = $user;

        return $this;
    }

    public static function logout() {
        unset($_SESSION['user']);
        session_destroy();
    }

    public function getById($id, $returnExists = false) {
        $query = $this->db->query('select')
            ->from('users')
            ->where('id = :id', [':id' => $id])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get user');
        elseif ($returnExists && $query->failed()) return false;
        elseif (!$returnExists && $query->count() == 0) throw new Exception('user does not exist');
        elseif ($returnExists) return $query->count() == 1;

        $user = $query->fetch()[0];
        $this->user = $user;
        return $this;
    }

    public function getByEmail($email, $returnExists = false) {
        $query = $this->db->query('select')
            ->from('users')
            ->where('email = :e', [':e' => $email])
            ->execute();

        if ($query->failed() && !$returnExists) throw new Exception('failed to get user');
        elseif ($returnExists && $query->failed()) return false;
        elseif (!$returnExists && $query->count() == 0) throw new Exception('user does not exist');
        elseif ($returnExists) return $query->count() == 1;

        $user = $query->fetch()[0];
        $this->user = $user;
        return $this;
    }

    public function getSelf() {
        $auth = new OAuth2($this->db);
        $this->getById($auth->getToken()['user_id']);
        return $this;
    }

    public function isActivated() {
        return $this->user['activated'] == 1;
    }

    public function getPermissions() {
        $query = $this->db->query('select')
            ->columns(['permission'])
            ->from('permissions p')
            ->join('left', 'user_permissions_rel upr', 'upr.permission_id = p.id')
            ->where('upr.user_id = :id', [':id' => $this->user['id']])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get user permissions');

        $permissions = array_map(function($var) { return $var['permission']; }, $query->fetch());
        return $permissions;
    }

    public function hasPermission($permission) {
        return in_array($permission, $this->getPermissions($this->user['id']));
    }

    public function addPermission($permission) {
        $permissions = new Permissions($this->db);
        $p = $permissions->getPermission($permission);

        if ($this->hasPermission($permission)) return true;

        CRUD::insert($this->db, 'user_permissions_rel', CRUD::compile([
            'user_id' => $this->user['id'],
            'permission_id' => $p['id']
        ]));

        return true;
    }

    public function removePermission($permission) {
        $permissions = new Permissions($this->db);
        $p = $permissions->getPermission($permission);

        if (!$this->hasPermission($permission)) return true;

        CRUD::delete($this->db, 'user_permissions_rel', [
            'expression' => 'user_id = :u && permission_id = :p',
            'data' => [':u' => $this->user['id'], ':p' => $p['id']]
        ]);

        return true;
    }

    public function hasPasswordRequestSent($returnRequest = false) {
        $query = $this->db->query('select')
            ->from('users_password_reset_requests')
            ->where('user_id = :uid && expires > now()', [':uid' => $this->user['id']])
            ->order_by('expires', 'DESC')
            ->execute();

        if ($query->failed()) throw new Exception('failed to check for an existing request');
        if ($returnRequest) return $query->fetch()[0];
        else return $query->count() > 0;
    }

    public static function register(DB $db, $email, $name, $password, $activationcode = null) {
        $user = new User($db);
        if ($user->getByEmail($email, true)) throw new Exception('email already registered');

        if (!$activationcode) $activationcode = hash('SHA512', mt_rand(100000, 999999).time().uniqid());
        $id = CRUD::insert($db, 'users', CRUD::compile([
            'email'          => $email,
            'password'       => $password,
            'firstname'      => $name['first'],
            'lastname'       => $name['last'],
            'created'        => ['now()'],
            'activated'      => false,
            'activationcode' => $activationcode
        ]));
        return $id;
    }

    public static function activate(DB $db, User $user, $email, $code) {
        if ($user->info()['activationcode'] != $code) throw new Exception('invalid activation code');
        CRUD::update($db, 'users', CRUD::compile([
            'activated' => true
        ]), [
            'expression' => 'email = :e && activationcode = :a',
            'data'       => [':e' => $email, ':a' => $code]
        ]);
        return true;
    }

    public static function resetPasswordRequest(DB $db, User $user, $code = null) {
        if ($user->hasPasswordRequestSent()) throw new Exception('already sent password reset request.');
        if (!$code) $code = hash('SHA512', mt_rand(100000, 999999).time().uniqid());
        CRUD::insert($db, 'users_password_reset_requests', CRUD::compile([
            'user_id'   => $user->info()['id'],
            'code'      => $code,
            'expires'   => date('Y-m-d h:i:S', strtotime('+1 day'))
        ]));

        return true;
    }

    public static function resetPassword(DB $db, User $user, $password, $code) {
        $request = $user->hasPasswordRequestSent(true);
        if ($code != $request['code']) throw new Exception('invalid reset code');

        CRUD::update($db, 'users', CRUD::compile([
            'password' => $password,
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        CRUD::delete($db, 'users_password_reset_requests', [
            'expression'    => 'id = :id',
            'data'          => [':id' => $request['id']]
        ]);
    }

    public static function update(DB $db, User $user, &$reactivate, $email, $name, $activationcode = null) {
        $reactivate = $user->info()['email'] != $email;

        if (!$activationcode) $activationcode = hash('SHA512', mt_rand(100000, 999999).time().uniqid());
        CRUD::update($db, 'users', CRUD::compile([
            'email'     => $email,
            'firstname' => $name['first'],
            'lastname'  => $name['last'],
            'activated' => $reactivate ? 3 : 1,
            'activationcode' => $reactivate ? $activationcode : $user->info()['activationcode']
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        return true;
    }

    public static function changePassword(DB $db, User $user, $password) {
        CRUD::update($db, 'users', CRUD::compile([
            'password' => $password,
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        return true;
    }

    public static function delete(DB $db, User $user, $email, $password, $useplaintextpw = false) {
        if ($user->info()['email'] != $email) throw new Exception('invalid email');
        if ($useplaintextpw && $password != $user->info()['password']) throw new Exception('invalid password');
        if (!$useplaintextpw && !password_verify($password, $user->info()['password'])) throw new Exception('invalid password');

        CRUD::delete($db, 'users', [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        return true;
    }
}
