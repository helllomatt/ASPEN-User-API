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

    /**
     * Returns the information about the user
     *
     * @return array
     */
    public function info() {
        return $this->user;
    }

    /**
     * Logs a user in, for SESSION based authentication
     *
     * @param  string $username
     * @param  string $password
     * @return Users\User
     */
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

    /**
     * Logs a user out, when using SESSION based auth
     *
     * @return void
     */
    public static function logout() {
        unset($_SESSION['user']);
        session_destroy();
    }

    /**
     * Gets a user by their ID
     *
     * @param  int  $id
     * @param  boolean $returnExists
     * @return Users\User
     */
    public function getById($id, $returnExists = false) {
        $query = $this->db->query('select')
            ->from('users')
            ->where('id = :id', [':id' => $id])
            ->execute();

        if ($query->failed()) throw new Exception('Failed to get user.');
        elseif ($returnExists && $query->failed()) return false;
        elseif (!$returnExists && $query->count() == 0) throw new Exception('User does not exist.');
        elseif ($returnExists) return $query->count() == 1;

        $user = $query->fetch()[0];
        $this->user = $user;
        return $this;
    }

    /**
     * Gets a user by their email
     *
     * @param  string  $email
     * @param  boolean $returnExists
     * @return Users\User
     */
    public function getByEmail($email, $returnExists = false) {
        $query = $this->db->query('select')
            ->from('users')
            ->where('email = :e', [':e' => $email])
            ->execute();

        if ($query->failed()) throw new Exception('Failed to get user.');
        elseif ($returnExists && $query->failed()) return false;
        elseif (!$returnExists && $query->count() == 0) throw new Exception('User does not exist.');
        elseif ($returnExists) return $query->count() == 1;

        $user = $query->fetch()[0];
        $this->user = $user;
        return $this;
    }

    /**
     * Gets a user based on their token
     *
     * @return Users\User
     */
    public function getSelf() {
        $auth = new OAuth2($this->db);
        $this->getById($auth->getToken()['user_id']);
        return $this;
    }

    /**
     * Returns the user's activation status
     *
     * @return boolean
     */
    public function isActivated() {
        return $this->user['activated'] == 1;
    }

    /**
     * Gets a user's permissions
     *
     * @return array
     */
    public function getPermissions() {
        $query = $this->db->query('select')
            ->columns(['permission'])
            ->from('permissions p')
            ->join('left', 'user_permissions upr', 'upr.permission_id = p.id')
            ->where('upr.user_id = :id', [':id' => $this->user['id']])
            ->execute();

        if ($query->failed()) throw new Exception('Failed to get user permissions.');

        $permissions = array_map(function($var) { return $var['permission']; }, $query->fetch());
        return $permissions;
    }

    /**
     * Checks to see if a user has permission to do something
     *
     * @param  string  $permission
     * @return boolean
     */
    public function hasPermission($permission) {
        return in_array($permission, $this->getPermissions($this->user['id']));
    }

    /**
     * Gives a user a permission
     *
     * @param string $permission
     */
    public function addPermission($permission) {
        $permissions = new Permissions($this->db);
        $p = $permissions->getPermission($permission);

        if ($this->hasPermission($permission)) return true;

        CRUD::insert($this->db, 'user_permissions', CRUD::compile([
            'user_id' => $this->user['id'],
            'permission_id' => $p['id']
        ]));

        return true;
    }

    /**
     * Removes a permission from a user
     *
     * @param  string $permission
     * @return boolean
     */
    public function removePermission($permission) {
        $permissions = new Permissions($this->db);
        $p = $permissions->getPermission($permission);

        if (!$this->hasPermission($permission)) return true;

        CRUD::delete($this->db, 'user_permissions', [
            'expression' => 'user_id = :u && permission_id = :p',
            'data' => [':u' => $this->user['id'], ':p' => $p['id']]
        ]);

        return true;
    }

    /**
     * Checks to see if the user has already requested a password reset
     *
     * @param  boolean $returnRequest
     * @return boolean
     */
    public function hasPasswordRequestSent($returnRequest = false) {
        $query = $this->db->query('select')
            ->from('user_password_reset_requests')
            ->where('user_id = :uid && expires > now()', [':uid' => $this->user['id']])
            ->order_by('expires', 'DESC')
            ->execute();

        if ($query->failed()) throw new Exception('Failed to check for an existing password request.');
        if ($returnRequest) return $query->fetch()[0];
        else return $query->count() > 0;
    }

    /**
     * Registers a new user
     *
     * @param  DB     $db
     * @param  string $email
     * @param  string $name
     * @param  string $password
     * @param  string $activationcode
     * @return int
     */
    public static function register(DB $db, $email, $name, $password, $activationcode = null) {
        $user = new User($db);
        if ($user->getByEmail($email, true)) throw new Exception('That email is already registered to an account.');

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

    /**
     * Activates a user account
     *
     * @param  DB     $db
     * @param  User   $user
     * @param  string $email
     * @param  string $code
     * @return boolean
     */
    public static function activate(DB $db, User $user, $email, $code) {
        if ($user->info()['activationcode'] != $code) throw new Exception('Invalid activation code');
        CRUD::update($db, 'users', CRUD::compile([
            'activated' => true
        ]), [
            'expression' => 'email = :e && activationcode = :a',
            'data'       => [':e' => $email, ':a' => $code]
        ]);
        return true;
    }

    /**
     * Creates a new reset request for a user's password
     *
     * @param DB     $db
     * @param User   $user
     * @param string
     */
    public static function resetPasswordRequest(DB $db, User $user, $code = null) {
        if ($user->hasPasswordRequestSent()) throw new Exception('Password request already generated.');
        if (!$code) $code = hash('SHA512', mt_rand(100000, 999999).time().uniqid());
        CRUD::insert($db, 'user_password_reset_requests', CRUD::compile([
            'user_id'   => $user->info()['id'],
            'code'      => $code,
            'expires'   => date('Y-m-d h:i:S', strtotime('+1 day'))
        ]));

        return true;
    }

    /**
     * Resets a user's password
     *
     * @param DB     $db
     * @param User   $user
     * @param string $password
     * @param string $code
     */
    public static function resetPassword(DB $db, User $user, $password, $code) {
        $request = $user->hasPasswordRequestSent(true);
        if ($code != $request['code']) throw new Exception('Invalid password reset code.');

        CRUD::update($db, 'users', CRUD::compile([
            'password' => $password,
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        CRUD::delete($db, 'user_password_reset_requests', [
            'expression'    => 'id = :id',
            'data'          => [':id' => $request['id']]
        ]);
    }

    /**
     * Updates a user's information
     *
     * @param  DB     $db
     * @param  User   $user
     * @param  boolean $reactivate
     * @param  string $email
     * @param  string $name
     * @param  string $activationcode
     * @return boolean
     */
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

    /**
     * Changes a user's password
     *
     * @param  DB     $db
     * @param  User   $user
     * @param  string $password
     * @return boolean
     */
    public static function changePassword(DB $db, User $user, $password) {
        CRUD::update($db, 'users', CRUD::compile([
            'password' => $password,
        ]), [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        return true;
    }

    /**
     * Deletes a user's account
     *
     * @param  DB      $db
     * @param  User    $user
     * @param  string  $email
     * @param  string  $password
     * @param  boolean $useplaintextpw
     * @return boolean
     */
    public static function delete(DB $db, User $user, $email, $password, $useplaintextpw = false) {
        if ($user->info()['email'] != $email) throw new Exception('Invalid email address.');
        if ($useplaintextpw && $password != $user->info()['password']) throw new Exception('Invalid password');
        if (!$useplaintextpw && !password_verify($password, $user->info()['password'])) throw new Exception('Invalid password');

        CRUD::delete($db, 'users', [
            'expression'    => 'id = :id',
            'data'          => [':id' => $user->info()['id']]
        ]);

        return true;
    }
}
