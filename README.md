# Jitsi Go OpenID

Jitsi Go OpenID provides an authentication adapter for giving [Jitsi](https://jitsi.org/) the ability to use single sign-on via [OpenID Connect](https://openid.net/connect/).

Tested to work with:
- [x] goauthentik

This code is heavily inspired by https://github.com/bluffy/jitsi-oidc

## Deployment

This image is available in the [Docker Hub](https://hub.docker.com/repository/docker/mod242/jitsi-go-openid) and can be easily deployed by using docker compose.

### Example Configuration (.env or environment Variables)

```env
JITSI_SECRET=xxxxx           # Must match the jwt_secret from your Jitsi configuration
JITSI_URL=https://xxxxx      # Base URL of your Jitsi instance
JITSI_SUB=xxxx               # Must match the JWT_APP_ID from your Jitsi configuration
ISSUER_BASE_URL=xxxx         # Base URL of your OpenID Connect provider
BASE_URL=https://xxxx        # Public base URL of this application (should run behind a reverse proxy)
CLIENT_ID=xxxxxxx            # Client ID from your OAuth provider
SECRET=xxxxx                 # Client secret from your OAuth provider
PREJOIN=false                # Whether the prejoin page should be displayed again after authentication
NAME_KEY=name                # Key for the user's name from the OAuth token (defaults to 'name', but can be 'given_name' or any other key present in the token)
DEEPLINK=true                # Whether the callback should use a deep link for redirect to ensure the originating client (Desktop, iOS, Android) is used
```

### Integration with Jitsi Meet on Docker
This project has been tested with [Jitsi Meet on Docker](https://github.com/jitsi/docker-jitsi-meet). To integrate this project, the provided Docker container should be started alongside Jitsi. If you are using a custom Docker network for Jitsi, the container should run within this network. To make the endpoint of this project available, it is recommended to use the Nginx container provided by Jitsi. According to the Jitsi Docker guidelines, you can create a "custom-meet.conf" file to publish this service. Example:

```nginx
location /jitsi-openid/ {
    proxy_pass http://jitsi-openid:3001/;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_buffering off;
    proxy_set_header Host $host;
}
```

This will expose the necessary service under the URL of the Jitsi conference server at /jitsi-openid (e.g., `https://conference.url.com/jitsi-openid`).

### Adjusting the .env File for Jitsi Docker
Lastly, the .env file for Jitsi Docker needs to be adjusted:

- `ENABLE_AUTH` must be enabled.
- `JWT_APP_ID` should be set to the URL of the server (e.g., `conference.yoururl.com`) and match the configuration of this service.
- `JWT_APP_SECRET` must be set and match the configuration of this service.
- `JWT_ACCEPTED_ISSUERS` should be set to `jitsi`.
- `JWT_ACCEPTED_AUDIENCES` should be set to `jitsi`.
- `AUTH_TYPE` should be set to `jwt`.
- `TOKEN_AUTH_URL` must be set in the following format to this service:
`https://conference.yoururl.com/jitsi-openid/authenticate?state={state}&room={room}`

### Setting Up the OAuth Provider
An OAuth2/OpenID Provider (like Authentik) must be set up. 
The App ID and Client Secret assigned during this setup must be configured for this service. 
Lastly the Callback URL should be set to the Base URL + /callback of this service (e.g., `https://conference.yoururl.com/jitsi-openid/callback`). 