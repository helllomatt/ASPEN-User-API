# Generating JWT Keys

In a terminal, type this out:
```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl pkey -in private.pem -out public.pem -pubout
```

Then, move those anywhere you want and load them into the configuration from the `index.php` file.

```php
ASPEN\Config::loadKeys('private.pem', 'public.pem');
```

From there, you're all set!
> There must be a public and private key.


# Authenticating Users

```
v1/users/authenticate
```

|parameter|value|description
|---|---|---
|grant_type|password|type of grant to give
|client_id|_yourclient_|client to grant against
|username|_username_|user's login username
|password|_password_|user's password

__Response__
```json
{
  "access_token": "<jwt token>",
  "expires_in": 86400,
  "token_type": "bearer",
  "scope": null,
  "refresh_token": "<refresh_token>"
}
```

# Validating Authentication

```
v1/users/validate-authentication
```

__Headers__
```
Authorization: Bearer <token>
```

__Response__
```json
// successful
{
  "status": "success",
  "data": []
}

// failure
{
  "status": "error",
  "message": "Unauthorized."
}
```

# Refreshing JWTs

```
v1/users/authenticate
```

|parameter|value|description
|---|---|---
|grant_type|refresh_token|type of grant to give
|client_id|_client id_|the client id to authenticate against
|refresh_token|_refresh token_|the refresh token given when authenticating last time

__Response__
```json
{
  "access_token": "<jwt token>",
  "expires_in": 86400,
  "token_type": "bearer",
  "scope": null,
  "refresh_token": "<refresh_token>"
}
```

# Registering User

```
v1/users/register
```

__Method__ `POST`

__Headers__ `Authorization: Bearer <token>`

|parameter|description
|---|---
|name|User's first _and_ last name
|email|Email address
|password|Password

__Response__
```json
// success
{
    "status": "success",
    "data": {
        "id": 0
    }
}

// error
{
    "status": "fail",
    "data": {
        "message": "bad email (example)",
        "code": 10
    }
}
```
