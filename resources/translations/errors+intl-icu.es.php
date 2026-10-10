<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

return [
    // Form.
    'Invalid form data.' =>
        'Datos de formulario inválidos.',

    // Configuration.
    'The database URL is not configured: set AUTH_DATABASE_URL (or DATABASE_URL).' =>
        'La URL de la base de datos no está configurada: define AUTH_DATABASE_URL (o DATABASE_URL).',
    'The path of the htpasswd file is not configured: set AUTH_HTPASSWD_PATH.' =>
        'La ruta del archivo htpasswd no está configurada: define AUTH_HTPASSWD_PATH.',
    'The htpasswd file "{path}" can not be read.' =>
        'No se puede leer el archivo htpasswd "{path}".',
    'The URL of Keycloak is not configured: set AUTH_KEYCLOAK_URL.' =>
        'La URL de Keycloak no está configurada: define AUTH_KEYCLOAK_URL.',
    'The realm of Keycloak is not configured: set AUTH_KEYCLOAK_REALM.' =>
        'El realm de Keycloak no está configurado: define AUTH_KEYCLOAK_REALM.',
    'The client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_ID.' =>
        'El cliente de Keycloak no está configurado: define AUTH_KEYCLOAK_CLIENT_ID.',
    'The secret of the client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_SECRET.' =>
        'El secreto del cliente de Keycloak no está configurado: define AUTH_KEYCLOAK_CLIENT_SECRET.',
    'The redirect URI of Keycloak is not configured: set AUTH_KEYCLOAK_WEB_REDIRECT_URI.' =>
        'La URI de redirección de Keycloak no está configurada: define AUTH_KEYCLOAK_WEB_REDIRECT_URI.',
    'The value of {variable} "{value}" is not valid: it must be an address that starts with http:// or https://.' =>
        'El valor de {variable} "{value}" no es válido: debe ser una dirección que empiece con http:// o https://.',
    'The audience of the API is not configured: set AUTH_KEYCLOAK_API_AUDIENCE, or the client with AUTH_KEYCLOAK_CLIENT_ID.' =>
        'La audiencia de la API no está configurada: define AUTH_KEYCLOAK_API_AUDIENCE, o el cliente con AUTH_KEYCLOAK_CLIENT_ID.',
    'Keycloak is asked about the tokens with a client, and it is not configured: set AUTH_KEYCLOAK_CLIENT_ID and AUTH_KEYCLOAK_CLIENT_SECRET (or the ones of the API, AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET), or turn the introspection off with AUTH_KEYCLOAK_API_INTROSPECTION=false.' =>
        'A Keycloak se le consulta por los tokens con un cliente, y no está configurado: define AUTH_KEYCLOAK_CLIENT_ID y AUTH_KEYCLOAK_CLIENT_SECRET (o los de la API, AUTH_KEYCLOAK_API_CLIENT_ID y AUTH_KEYCLOAK_API_CLIENT_SECRET), o desactiva la introspección con AUTH_KEYCLOAK_API_INTROSPECTION=false.',
    'You must be authenticated to access {path}.' =>
        'Debes iniciar sesión para acceder a {path}.',
    'You do not have access to {path}: your user has no roles.' =>
        'No tienes acceso a {path}: tu usuario no tiene roles.',
    'You do not have access to {path}. These roles give access: {roles}.' =>
        'No tienes acceso a {path}. Estos roles dan acceso: {roles}.',
    'No channel of authentication matches the request.' =>
        'Ningún canal de autenticación corresponde a la petición.',
    'The query "sql_is_active" failed: {error}. If the table has no column "{column}", give your own query in "sql_is_active" or turn the check off with false.' =>
        'La consulta "sql_is_active" falló: {error}. Si la tabla no tiene la columna "{column}", entrega tu propia consulta en "sql_is_active" o desactiva la comprobación con false.',
    'The protected path "{path}" is not valid.' =>
        'La ruta protegida "{path}" no es válida.',
    'The path of the API "{path}" is not valid.' =>
        'La ruta de la API "{path}" no es válida.',
    'The realm of the API must be a text without quotes, backslashes or control characters.' =>
        'El realm de la API debe ser un texto sin comillas, barras invertidas ni caracteres de control.',
    'The refresh interval must be a number of seconds, 0 or more.' =>
        'El intervalo de actualización debe ser un número de segundos, 0 o más.',

    // Keycloak.
    'User identity not found in keycloak user info.' =>
        'No se encontró la identidad del usuario en la información de usuario de Keycloak.',
    'Failed to get user info: {error}' =>
        'No se pudo obtener la información del usuario: {error}',
    'Failed to exchange code for token: {error}' =>
        'No se pudo intercambiar el código por un token: {error}',
    'Failed to refresh token: {error}' =>
        'No se pudo renovar el token: {error}',

    // Keycloak callback. The description comes from Keycloak: it is shown as is.
    '{message}' =>
        '{message}',
    'No state parameter found in the session.' =>
        'No se encontró el parámetro state en la sesión.',
    'State parameter does not match the stored state in the session.' =>
        'El parámetro state no coincide con el almacenado en la sesión.',
    'The login was not completed.' =>
        'El inicio de sesión no se completó.',
    'The Keycloak provider requires "league/oauth2-client". Run: composer require league/oauth2-client' =>
        'El proveedor de Keycloak requiere "league/oauth2-client". Ejecuta: composer require league/oauth2-client',
    'The Keycloak provider requires "firebase/php-jwt". Run: composer require firebase/php-jwt' =>
        'El proveedor de Keycloak requiere "firebase/php-jwt". Ejecuta: composer require firebase/php-jwt',
    'Failed to validate the token: {error}' =>
        'No se pudo validar el token: {error}',
    'Failed to introspect the token: {error}' =>
        'No se pudo consultar a Keycloak por el token: {error}',
    'The token is not active.' =>
        'El token no está activo.',
    'The user of the introspection is not the user of the token.' =>
        'El usuario de la introspección no es el usuario del token.',
    'The audience of the API "{audience}" is not the client "{client}": Keycloak is asked about the tokens of the API by the client, and it only answers about the tokens that have it in their audience. Use the client as the audience, or turn the introspection off.' =>
        'La audiencia de la API "{audience}" no es el cliente "{client}": a Keycloak se le consulta por los tokens de la API con el cliente, y solo responde por los tokens que lo tienen en su audiencia. Usa el cliente como audiencia, o desactiva la introspección.',
    'The token is not an access token.' =>
        'El token no es un token de acceso.',
    'The client of the API needs its ID and its secret, both: set AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET.' =>
        'El cliente de la API necesita su ID y su secreto, los dos: define AUTH_KEYCLOAK_API_CLIENT_ID y AUTH_KEYCLOAK_API_CLIENT_SECRET.',
    'The audience of the token is not this API.' =>
        'La audiencia del token no es esta API.',
    'The audience of the token is not this client.' =>
        'La audiencia del token no es este cliente.',
    'The nonce of the token is not the one of the login.' =>
        'El nonce del token no es el del inicio de sesión.',
    'The token was not given to this client.' =>
        'El token no fue entregado a este cliente.',
    'The issuer of the token is not the realm.' =>
        'El emisor del token no es el realm.',
    'The user of the user info is not the user of the token.' =>
        'El usuario de la información de usuario no es el usuario del token.',
    'The ID token was not received.' =>
        'No se recibió el token de identidad.',
    'The user of the ID token is not the user of the access token.' =>
        'El usuario del token de identidad no es el usuario del token de acceso.',
    'The name "{name}" is not valid for a table or a column.' =>
        'El nombre "{name}" no es válido para una tabla o una columna.',
    'No authorization code received.' =>
        'No se recibió el código de autorización.',
    'Authentication failed: {error}' =>
        'La autenticación falló: {error}',
    'The session can not be renewed in place: use the session of Mezzio\\Session\\SessionMiddleware.' =>
        'La sesión no se puede renovar en el lugar: usa la sesión de Mezzio\\Session\\SessionMiddleware.',

    // The provider of the application (AUTH_PROVIDER).
    'There are no providers: tag the service of each one with derafu_auth.provider.' =>
        'No hay proveedores: etiqueta el servicio de cada uno con derafu_auth.provider.',
    'AUTH_PROVIDER is not set. Choose one of: {providers}.' =>
        'AUTH_PROVIDER no está definida. Elige una de: {providers}.',
    'AUTH_PROVIDER "{name}" is not a provider. Choose one of: {providers}.' =>
        'AUTH_PROVIDER "{name}" no es un proveedor. Elige una de: {providers}.',
    'This provider has no callback.' => 'Este proveedor no tiene callback.',
    'The limit of the failed logins needs a PSR-6 cache pool: the application must have a service for Psr\\Cache\\CacheItemPoolInterface.' =>
        'El límite de los inicios de sesión fallidos necesita un pool de caché PSR-6: la aplicación debe tener un servicio para Psr\\Cache\\CacheItemPoolInterface.',

    // The account of the user.
    'You must be logged in to access the requested page {path}' => 'Debes iniciar sesión para acceder a la página solicitada {path}',
    'The request has no session.' => 'La solicitud no tiene sesión.',
    'This provider has no tokens for the API.' => 'Este proveedor no tiene tokens para la API.',
    'The request does not come from this site.' => 'La solicitud no viene de este sitio.',

    // The group file of the `.htpasswd` provider.
    'The group file "{path}" can not be read.' => 'El archivo de grupos "{path}" no se puede leer.',

    // The tokens of the API of Keycloak.
    'The token is not for the user of this session.' => 'El token no es del usuario de esta sesión.',
    'The token that Keycloak gave is not one for the API.' => 'El token que entregó Keycloak no es uno para la API.',
    'Keycloak did not revoke the token (HTTP status {status}).' => 'Keycloak no revocó el token (estado HTTP {status}).',
    'Keycloak did not accept the offline token.' => 'Keycloak no aceptó el token offline.',
    'Your user is disabled.' => 'Tu usuario está deshabilitado.',
    'Your user has actions pending in Keycloak (a password to change, an email to verify...): complete them and try again.' =>
        'Tu usuario tiene acciones pendientes en Keycloak (cambiar la contraseña, verificar el correo...): complétalas e inténtalo de nuevo.',
    'The password or the code of the second factor is not valid.' => 'La contraseña o el código del segundo factor no es válido.',
    'The password is not valid, or the code of the second factor is missing (your user has one).' =>
        'La contraseña no es válida, o falta el código del segundo factor (tu usuario tiene uno).',
    'Keycloak did not let the sessions be read (HTTP status {status}).' => 'Keycloak no dejó leer las sesiones (estado HTTP {status}).',
    'The token of your session does not have the role {role} of the client {client}, that Keycloak asks to read the sessions. Add it to the scope of the client {application}.' =>
        'El token de tu sesión no tiene el rol {role} del cliente {client}, que Keycloak pide para leer las sesiones. Agrégalo al scope del cliente {application}.',
    'The token of your session does not have the role {role} of the client {client}, that Keycloak asks to revoke a token. Add it to the scope of the client {application}.' =>
        'El token de tu sesión no tiene el rol {role} del cliente {client}, que Keycloak pide para revocar un token. Agrégalo al scope del cliente {application}.',
    'Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.' =>
        'Demasiados intentos fallidos de inicio de sesión. Inténtalo de nuevo en {minutes, plural, one {# minuto} other {# minutos}}.',
    'Failed to read the account of Keycloak: {error}' => 'No se pudo leer la cuenta en Keycloak: {error}',
    'The password is not valid.' => 'La contraseña no es válida.',
    'Keycloak does not let this application make tokens with a password: turn on the direct access grants of its client.' =>
        'Keycloak no deja que esta aplicación cree tokens con una contraseña: activa los direct access grants de su cliente.',
    'Failed to ask Keycloak for a token: {error}' => 'No se pudo pedir el token a Keycloak: {error}',
    'The user has no such token.' => 'El usuario no tiene ese token.',
    'There is no session with Keycloak.' => 'No hay una sesión con Keycloak.',
    'There is no user in the session.' => 'No hay un usuario en la sesión.',
];
