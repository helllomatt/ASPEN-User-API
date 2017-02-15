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

    public function getById($id) {
        $query = $this->db->query('select')
            ->from('users')
            ->where('id = :id', [':id' => $id])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get user');
        if ($query->count() == 0) throw new Exception('user does not exist');

        $user = $query->fetch()[0];
        $this->user = $user;
        return $this;
    }

    public function getSelf() {
        $auth = new OAuth2();
        $this->getById($auth->getToken()['user_id']);
        return $this;
    }

    public function getPermissions($userId) {
        $query = $this->db->query('select')
            ->columns(['permission'])
            ->from('permissions p')
            ->join('left', 'user_permissions_rel upr', 'upr.permission_id = p.id')
            ->where('upr.user_id = :id', [':id' => $userId])
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
}
