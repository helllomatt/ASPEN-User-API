# Users

## Creating the user object
```php
$db = (new Double\DB())->connect($host, $username, $password, $table);
$user = new Users\User($db);
```

## Getting users
```php
// getting self
$user->getSelf();

// getting by id
$user->getById($id);

// getting information
$user->getSelf()->info();
```

## Checking user permissions
```php
$user->getSelf()->hasPermission($permission_name);
```

returns `true` or `false`

## Managing user permissions
```php
// adding
$user->getSelf()->addPermission($permission_name);

// removing
$user->getSelf()->removePermission($permission_name);
```

returns `true`


# Permissions

## Creating the permissions object
```php
$db = (new Double\DB())->connect($host, $username, $password, $table);
$permissions = new Users\Permissions($db);
```

## Managing permissions
```php
// creating
$permissions->create($permission_name);

// deleting
$permissions->delete($permission_name);
```

> if you delete a permission, it will delete all of the relational user permissions forever
