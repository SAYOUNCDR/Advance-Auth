## What this auth template covers

This authentication template provides a comprehensive overview of the key components and features included in the authentication system. It covers the following aspects:

1. **User Registration**: User enters email , password and name to create an account.

a. If the email is already in use, an error message is displayed.
b. If not present in db and email is valid , a verification email is sent to the user. Verify the email to activate the account.

2. **User Login**: Users can log in using their registered email and password.

a. If credentials are wrong, an error message is displayed.
b. If credentials are correct a onetime password (OTP) is sent to the user's email for two-factor authentication (2FA).
c. Otp is verified to complete the login process. if OTP is incorrect, an error message is displayed.
d. If OTP is correct, user is logged in and a access and refresh token is generated.
e. Session is created to keep the user logged in and only one active session is allowed per user.

NOTES:
NOSQLi injection - Learn about this ( for preventing this mongo sanitize is used )
it basically does is that

input
{
"name": { "$ne": null },
"email": "sayounparui45@gmail.com",
"password": "Sayoun@123"
}

will remove $ne and output will be
{
"name": {},
"email": "sayounparui45@gmail.com",
"password": "Sayoun@123"
}
