<?php

namespace Users;

use Double\DB;

interface UserInterface {
    public function info();
    public function login($username, $password);
    public static function logout();
    public function getById($id, $returnExists = false);
    public function getByEmail($email, $returnExists = false);
    public function getSelf();
    public function isActivated();
    public function getPermissions();
    public function hasPermission($permission);
    public function addPermission($permission);
    public function removePermission($permission);
    public function hasPasswordRequestSent($returnRequest = false);
    public static function register(DB $db, $email, $name, $password, $activationcode = null);
    public static function activate(DB $db, User $user, $email, $code);
    public static function resetPasswordRequest(DB $db, User $user, $code = null);
    public static function resetPassword(DB $db, User $user, $password, $code);
    public static function update(DB $db, User $user, &$reactivate, $email, $name, $activationcode = null);
    public static function changePassword(DB $db, User $user, $password);
    public static function delete(DB $db, User $user, $email, $password, $useplaintextpw = false);
}
