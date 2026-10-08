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
    'Database URL is required.' =>
        'La URL de la base de datos es obligatoria.',
    'The path of the htpasswd file is required.' =>
        'La ruta del archivo htpasswd es obligatoria.',
    'The htpasswd file "{path}" can not be read.' =>
        'No se puede leer el archivo htpasswd "{path}".',
    'Keycloak URL is required.' =>
        'La URL de Keycloak es obligatoria.',
    'Keycloak realm is required.' =>
        'El realm de Keycloak es obligatorio.',
    'Client ID is required.' =>
        'El ID de cliente es obligatorio.',
    'Client secret is required.' =>
        'El secreto de cliente es obligatorio.',
    'Redirect URI is required.' =>
        'La URI de redirección es obligatoria.',
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
    'The client of the API needs its ID and its secret, both.' =>
        'El cliente de la API necesita su ID y su secreto, los dos.',
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
];
