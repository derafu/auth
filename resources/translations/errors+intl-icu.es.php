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

    // Keycloak.
    'User identity not found in keycloak user info.' =>
        'No se encontró la identidad del usuario en la información de usuario de Keycloak.',
    'Failed to get user info: {error}' =>
        'No se pudo obtener la información del usuario: {error}',
    'Failed to exchange code for token: {error}' =>
        'No se pudo intercambiar el código por un token: {error}',
    'Failed to refresh token: {error}' =>
        'No se pudo renovar el token: {error}',
    'Invalid JWT token format.' =>
        'Formato de token JWT inválido.',
    'Failed to decode JWT payload.' =>
        'No se pudo decodificar el contenido del token JWT.',
    'Failed to parse JWT payload JSON.' =>
        'No se pudo interpretar el JSON del contenido del token JWT.',
    'Failed to parse JWT token: {error}' =>
        'No se pudo interpretar el token JWT: {error}',

    // Keycloak callback. The description comes from Keycloak: it is shown as is.
    '{description}' =>
        '{description}',
    'Session not available.' =>
        'La sesión no está disponible.',
    'No state parameter found in the session.' =>
        'No se encontró el parámetro state en la sesión.',
    'State parameter does not match the stored state in the session.' =>
        'El parámetro state no coincide con el almacenado en la sesión.',
    'No authorization code received.' =>
        'No se recibió el código de autorización.',
    'Authentication failed: {error}' =>
        'La autenticación falló: {error}',
];
