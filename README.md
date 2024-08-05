# Jitsi Go OpenID

Jitsi Go OpenID provides an authentication adapter for giving [Jitsi](https://jitsi.org/) the ability to use single sign-on via [OpenID Connect](https://openid.net/connect/).

Tested to work with:
- [x] goauthentik

This code is heavily inspired by https://github.com/bluffy/jitsi-oidc

## Deployment

This image is available in the [Docker Hub](https://hub.docker.com/repository/docker/mod242/jitsi-go-openid) and can be easily deployed by using docker compose.

### Configuration Environment Variables


`JITSI_SECRET` - Must match the jwt_secret from your Jitsi configuration  
`JITSI_URL` - Base URL of your Jitsi instance  
`JITSI_SUB` - Must match the JWT_APP_ID from your Jitsi configuration  
`ISSUER_BASE_URL` - Base URL of your OpenID Connect provider  
`BASE_URL` - Public base URL of this application (should run behind a reverse proxy)  
`CLIENT_ID`- Client ID from your OAuth provider  
`SECRET` - Client secret from your OAuth provider  
`PREJOIN`- Whether the prejoin page should be displayed again after authentication  
`NAME_KEY` - Key for the user's name from the OAuth token (defaults to 'name', but can be 'given_name' or any other key present in the token)  
`DEEPLINK` - Whether the callback should use a deep link for redirect to ensure the originating client (Desktop, iOS, Android) is used  

Example (.env or environment Variables)

```env
JITSI_SECRET=89we7tsgf37iqewurtgwziuegskj
JITSI_URL=https://jitsi.mydomain.com
JITSI_SUB=jitsi
ISSUER_BASE_URL=https://authentik.mydomain.com/application/o/jitsi/
BASE_URL=https://jitsi.mydomain.com
CLIENT_ID=xxxxxxxxxxxx
SECRET=xxxxxxxxxxxxxxxxxxxxxxx
PREJOIN=false
DEEPLINK=true
NAME_KEY=name
```

### Integration with Jitsi Meet on Docker
This project has been tested with [Jitsi Meet on Docker](https://github.com/jitsi/docker-jitsi-meet). To integrate this project, the provided Docker container should be started alongside Jitsi. If you are using a custom Docker network for Jitsi, the container should run within this network. To make the endpoint of this project available, it is recommended to use the Nginx container provided by Jitsi. According to the Jitsi Docker guidelines, you can create a "custom-meet.conf" (The path in "Jitsi Meet on Docker" is ["/config/custom-meet.conf"](https://github.com/jitsi/docker-jitsi-meet/blob/d6b64a21b99cd46a664175d55525f78c08903637/web/rootfs/etc/cont-init.d/10-config#L114) file to publish this service. Example:

```nginx
location /jitsi-openid/ {
    proxy_pass http://jitsi-openid:3001/;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_buffering off;
    proxy_set_header Host $host;
}
```


This will expose the necessary service under the URL of the Jitsi conference server at /jitsi-openid (e.g., `https://conference.url.com/jitsi-openid`).

#### (Alternative) Routing via treafik

As an alternative to the "custom-meet.conf", if you are running behind a [treafik](https://traefik.io/traefik/) you can route request to `/jitsi-openid` to the "jitsi-go-openid"-container via treafik.
Keep in mind that the path must be stripped away before sending it to the "jitsi-go-openid"-container. Example:

```yaml
service:
    [...]
    jitsi-openid:
        image: mod242/jitsi-go-openid:latest
        labels:
        - "traefik.enable=true"
        - "traefik.http.services.srv-jitsi-oidc.loadbalancer.server.port=3001"
        - "traefik.http.middlewares.mw-strip-oidc-prefix.stripprefix.prefixes=/jitsi-openid"
        - "traefik.http.routers.rt-jitsi-oidc.middlewares=mw-strip-oidc-prefix"
        - "traefik.http.routers.rt-jitsi-oidc.service=srv-jitsi-oidc"
        - "traefik.http.routers.rt-jitsi-oidc.entrypoints=webtls"
        - "traefik.http.routers.rt-jitsi-oidc.rule=(Host(`jitsi.mydomain.com`) && PathPrefix(`/jitsi-openid`))"
        - "traefik.http.routers.rt-jitsi-oidc.tls=true"
        - "traefik.http.routers.rt-jitsi-oidc.tls.certResolver=your-letsencrypt-resolver"
        environment:
        - JITSI_SECRET=abcdf
        [...]
```

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