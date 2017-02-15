<?php

namespace Users;

use Double\DB;
use Basically\CRUD;
use Exception;

class Permissions {
    private $db;

    public function __construct(DB $db) {
        $this->db = $db;
    }

    public function permissionExists($name) {
        $query = $this->db->query('select')
            ->from('permissions')
            ->where('permission = :n', [':n' => $name])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get permisison');
        return $query->count() == 1;
    }

    public function getPermission($name) {
        $query = $this->db->query('select')
            ->from('permissions')
            ->where('permission = :n', [':n' => $name])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get permisison');
        if ($query->count() != 1) throw new Exception('permission does not exist');

        return $query->fetch()[0];
    }

    public function create($permission) {
        if ($this->permissionExists($permission)) throw new Exception('permission already exists');
        return CRUD::insert($this->db, 'permissions', CRUD::compile([
            'permission' => CRUD::sanitize($permission, ['string', 'required', 'match' => 'a-z-'])
        ]));
    }

    public function delete($permission) {
        if (!$this->permissionExists($permission)) throw new Exception('permission does not exist');
        $permission = $this->getPermission($permission);
        CRUD::delete($this->db, 'permissions', [
            'expression' => 'id = :id',
            'data' => [':id' => $permission['id']]
        ]);

        CRUD::delete($this->db, 'user_permissions_rel', [
            'expression' => 'permission_id = :pid',
            'data' => [':pid' => $permission['id']]
        ]);
    }
}
