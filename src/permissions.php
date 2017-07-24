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

    /**
     * Checks if a permission exists
     *
     * @param  string $name
     * @return boolean
     */
    public function permissionExists($name) {
        $query = $this->db->query('select')
            ->from('permissions')
            ->where('permission = :n', [':n' => $name])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get permisison');
        return $query->count() == 1;
    }

    /**
     * Gets a permission by it's name
     *
     * @param  string $name
     * @return array
     */
    public function getPermission($name) {
        $query = $this->db->query('select')
            ->from('permissions')
            ->where('permission = :n', [':n' => $name])
            ->execute();

        if ($query->failed()) throw new Exception('failed to get permisison');
        if ($query->count() != 1) throw new Exception('permission does not exist');

        return $query->fetch()[0];
    }

    /**
     * Creates a new permission
     *
     * @param  string $permission
     * @return int
     */
    public function create($permission) {
        if ($this->permissionExists($permission)) throw new Exception('permission already exists');
        return CRUD::insert($this->db, 'permissions', CRUD::compile([
            'permission' => CRUD::sanitize($permission, ['string', 'required', 'match' => 'a-z-'])
        ]));
    }

    /**
     * Deletes a permission and all of it's relational data
     *
     * @param  string $permission
     * @return void
     */
    public function delete($permission) {
        if (!$this->permissionExists($permission)) throw new Exception('permission does not exist');
        $permission = $this->getPermission($permission);
        CRUD::delete($this->db, 'permissions', [
            'expression' => 'id = :id',
            'data' => [':id' => $permission['id']]
        ]);

        CRUD::delete($this->db, 'user_permissions', [
            'expression' => 'permission_id = :pid',
            'data' => [':pid' => $permission['id']]
        ]);
    }
}