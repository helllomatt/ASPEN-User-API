# ASPEN User API
This is an API used to allow for user management using the ASPEN framework. Users can:

- Register new accounts
- Activate accounts
- Reset passwords via request
- Log in via OAuth2
- Update information (when logged in)
- Change their password (when logged in)

## How to install
There's two parts: firstly install the package, secondly set up the database.

Installing the package:
```
composer require helllomatt/aspen-user-api
```

Setting up the database:

1. Navigate to the package `.../vendor/helllomatt/aspen-user-api`
2. In the `src` folder you'll find `oauth.sql`
3. Import `oauth.sql` into your database

After that, you're ready to use the API.
