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

__Method__ `POST`
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

__Method__ `any`
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

__Method__ `POST`
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

# Registering a User

__Method__ `POST`
```
v1/users/register
```


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

# Activating a User

__Method__ `POST`
```
v1/users/activate
```


|parameter|description
|---|---
|email|user's email address
|code|activation code created at registration time.

__Response__
```json
// successful
{
    "status": "success",
    "data": {}
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

# Reset Password Request
__Method__ `POST`
```
v1/users/reset-password-request
```

|parameter|description
|---|---
|email|user's email address

__Response__
```json
// successful
{
    "status": "success",
    "data": {}
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

# Reset Password
__Method__ `POST`
```
v1/users/reset-password
```

|parameter|description
|---|---
|email|user's email address
|code|password reset code sent to them
|password|new password

__Response__
```json
// successful
{
    "status": "success",
    "data": {}
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

# Update user information
__Method__ `POST`
```
v1/users/update
```

__Headers__
```
Authorization: Bearer <token>
```

|parameter|description
|---|---
|email|same or new email address
|name|user's full name

__Response__
```json
// success
{
    "status": "success",
    "data": {
        "reactivate": false
    }
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

> Changing the email address requires the user to reactivate their account. They can continue to use it, but will be locked from continuing to do things that they were able to do with an activated account.
>
> If the user has not activated their account, then they will just need to do that with the newly provided email address

# Change a password
__Method__ `POST`
```
v1/users/change-password
```

__Headers__
```
Authorization: Bearer <token>
```

|parameter|description
|---|---|
|password|new password

__Response__
```json
// successful
{
    "status": "success",
    "data": {}
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

# Deleting account
__Method__ `POST`
```
v1/users/delete
```

__Headers__
```
Authorization: Bearer <token>
```

|parameter|description
|---|---
|email|current user's email
|password|current user's password

__Response__
```json
// successful
{
    "status": "success",
    "data": {}
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```

# Getting self
__Method__ `GET`
```
v1/users/self
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
    "data": {
        "user": {
            ...
        }
    }
}

// error
{
    "status": "error",
    "message": "somemessage"
}
```
