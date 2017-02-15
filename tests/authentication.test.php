<?php

namespace Users;

class AuthenticationTest extends \PHPUnit_Framework_TestCase {
    private static $db = null;

    public static function setUpBeforeClass() {
        static::$db = (new DB)->connect(database_host, database_username, database_password, database_name);
        static::$db->query('verbatim')
            ->sql(file_get_contents('src/oauth2.sql'))
            ->execute();
    }
}
