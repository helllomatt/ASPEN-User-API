<?php

namespace Users;

use Double\DB;

class UserTest extends \PHPUnit_Framework_TestCase {
    private static $db = null;

    public static function setUpBeforeClass() {
        static::$db = (new DB)->connect(database_host, database_username, database_password, database_name);
        echo 'Setting up test tables...'.PHP_EOL;
        foreach (explode(';', file_get_contents('src/oauth.sql')) as $query) {
            $query = trim($query);
            if ($query != '') static::$db->query('verbatim')->sql($query)->execute();
        }
    }

    public static function tearDownAfterClass() {
        echo PHP_EOL.'Dropping test tables...'.PHP_EOL;
        foreach (explode(';', file_get_contents('tests/drop.sql')) as $query) {
            $query = trim($query);
            if ($query != '') static::$db->query('verbatim')->sql($query)->execute();
        }
    }

    public function testRegistering() {
        $id = User::register(static::$db, 'john.smith@example.com', ['first' => 'John', 'last' => 'Smith'], 'pwd', 'code');
        $this->assertEquals(1, $id);
    }

    public function testRegisteringExisting() {
        $this->expectException('\Exception');
        User::register(static::$db, 'john.smith@example.com', ['first' => 'John', 'last' => 'Smith'], 'pwd');
    }

    public function testActivatedStatusAfterRegistration() {
        $this->assertFalse((new User(static::$db))->getById(1)->isActivated());
    }

    public function testActivating() {
        $user = (new User(static::$db))->getByEmail('john.smith@example.com');
        $this->assertTrue(User::activate(static::$db, $user, 'john.smith@example.com', 'code'));
    }

    public function testActivatedStatusAfterActivating() {
        $this->assertTrue((new User(static::$db))->getById(1)->isActivated());
    }

    public function testBadEmailActivation() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getByEmail('john.smih@example.com');
        $this->assertTrue(User::activate(static::$db, $user, 'john.smih@example.com', 'code'));
    }

    public function testBadCodeActivation() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getByEmail('john.smith@example.com');
        $this->assertTrue(User::activate(static::$db, $user, 'john.smith@example.com', ''));
    }

    public function testResetPasswordRequest() {
        $user = (new User(static::$db))->getByEmail('john.smith@example.com');
        $this->assertTrue(User::resetPasswordRequest(static::$db, $user, 'reset'));
    }

    public function testResetPasswordRequestAgain() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getByEmail('john.smith@example.com');
        User::resetPasswordRequest(static::$db, $user, 'reset');
    }

    public function testBadResetPasswordCode() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getById(1);
        User::resetPassword(static::$db, $user, 'pass', 'asdf');
    }

    public function testResetPassword() {
        $obj = (new User(static::$db));
        $user = $obj->getById(1);
        User::resetPassword(static::$db, $user, 'pass', 'reset');
        $this->assertEquals('pass', $obj->getById(1)->info()['password']);
        $this->assertFalse($user->hasPasswordRequestSent());
    }

    public function testUpdate() {
        $user = (new User(static::$db))->getById(1);
        $reactivate = false;
        User::update(static::$db, $user, $reactivate, 'john@example.com', ['first' => 'John', 'last' => 'S']);
        $user->getById(1); // update user info
        $this->assertEquals('john@example.com', $user->info()['email']);
        $this->assertEquals('S', $user->info()['lastname']);
        $this->assertTrue($reactivate);
    }

    public function testActivatedStatusAfterUpdating() {
        $this->assertFalse((new User(static::$db))->getById(1)->isActivated());
    }

    public function testChangingPassword() {
        $user = (new User(static::$db))->getById(1);
        User::changePassword(static::$db, $user, 'change');
        $user->getById(1); // update user info
        $this->assertEquals('change', $user->info()['password']);
    }

    public function testDeletingUserWithBadEmail() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getById(1);
        User::delete(static::$db, $user, 'john.smith@example.com', 'change', true);
    }

    public function testDeletingUserWithBadPassword() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getById(1);
        User::delete(static::$db, $user, 'john.smith@example.com', '');
    }

    public function testCreatingPermission() {
        $this->assertEquals(1, (new Permissions(static::$db))->create('test'));
    }

    public function testCreatingPermissionThatExists() {
        $this->expectException('\Exception');
        (new Permissions(static::$db))->create('test');
    }

    public function testAddingPermissionToUser() {
        $user = (new User(static::$db))->getById(1);
        $user->addPermission('test');
        $this->assertTrue($user->hasPermission('test'));
    }

    public function testAddingPermissionToUserAgain() {
        $this->assertTrue((new User(static::$db))->getById(1)->addPermission('test'));
    }

    public function testAddingBadPermissionToUser() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getById(1)->addPermission('asdf');
    }

    public function testGettingUsersPermissions() {
        $user = (new User(static::$db))->getById(1);
        $this->assertEquals(['test'], $user->getPermissions());
    }

    public function testRemovingPermissionFromUser() {
        $user = (new User(static::$db))->getById(1);
        $user->removePermission('test');
        $this->assertFalse($user->hasPermission('test'));
    }

    public function testRemovingBadPermissionFromUser() {
        $this->expectException('\Exception');
        $user = (new User(static::$db))->getById(1)->addPermission('asdf');
    }

    public function testDeletingPermission() {
        $permissions = (new Permissions(static::$db));
        $user = (new User(static::$db))->getById(1);
        $user->addPermission('test');

        $this->assertTrue($user->hasPermission('test'));
        $permissions->delete('test');
        $this->assertFalse($user->hasPermission('test'));
    }

    public function testDeletingUser() {
        $user = (new User(static::$db))->getById(1);
        User::delete(static::$db, $user, 'john@example.com', 'change', true);
        $this->expectException('\Exception');
        $user->getById(1);
    }
}
