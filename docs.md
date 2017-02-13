# Generating JWT Keys

In a terminal, type this out:
```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl pkey -in private.pem -out public.pem -pubout
```

Then, move those anywhere you want and load them into the configuration from the `index.php` file.

```
ASPEN\Config::loadKeys('private.pem', 'public.pem');
```

From there, you're all set!
> There must be a public and private key.


# Authenticating Users

```
users/authenticate
```

|parameter|value|description
|---|---|---
|grant_type|password|type of grant to give
|client_id|_yourclient_|client to grant against
|username|_username_|user's login username
|password|_password_|user's password

__Response__
```
{
  "access_token": "<token>",
  "expires_in": 86400,
  "token_type": "bearer",
  "scope": null,
  "refresh_token": "<refresh_token>"
}
```

# Validating Authentication

```
users/validate-authentication
```

__Headers__
```
Authorization: Bearer <token>
```

__Response__
```
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
