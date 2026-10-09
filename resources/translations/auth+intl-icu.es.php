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
    // Login.
    'Login' => 'Iniciar sesión',

    // Responses to the clients of the API.
    'Unauthorized' => 'No autorizado',
    'You need to send valid credentials to access this resource.' => 'Debes enviar credenciales válidas para acceder a este recurso.',

    // Login form (Provider/Database/Form/LoginForm.php).
    'Username' => 'Usuario',
    'Password' => 'Contraseña',

    // Flash messages.
    'Successfully logged in.' => 'Sesión iniciada correctamente.',
    'Invalid identity or password.' => 'Identidad o contraseña inválida.',
    'Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.' =>
        'Demasiados intentos fallidos de inicio de sesión. Inténtalo de nuevo en {minutes, plural, one {# minuto} other {# minutos}}.',
    'The session has been closed successfully.' => 'La sesión se cerró correctamente.',
    'You must be logged in to access the requested page {path}' => 'Debes iniciar sesión para acceder a la página solicitada {path}',

    // Profile (templates/auth/profile and the account controller).
    'Profile' => 'Perfil',
    'Logout' => 'Cerrar sesión',
    'Data' => 'Datos',
    'API' => 'API',
    'Session' => 'Sesión',
    'Yes' => 'Sí',
    'No' => 'No',
    'Your data' => 'Tus datos',
    'Edit your data' => 'Editar tus datos',
    'All the data of the provider' => 'Todos los datos del proveedor',
    'PHP session' => 'Sesión de PHP',
    'How to use the API' => 'Cómo usar la API',
    'Send your username and your password with each request, using HTTP Basic authentication:' => 'Envía tu usuario y tu contraseña en cada solicitud, con la autenticación HTTP Basic:',
    'Send a token of the API in the header of each request:' => 'Envía un token de la API en la cabecera de cada solicitud:',
    'See the documentation of the API' => 'Ver la documentación de la API',
    'Tokens of the API' => 'Tokens de la API',
    'Created' => 'Creado',
    'Last used' => 'Último uso',
    'Expires' => 'Vence',
    'Address' => 'Dirección',
    'Browser' => 'Navegador',
    'Revoke' => 'Revocar',
    'The token will stop working at once. Revoke it?' => 'El token dejará de funcionar de inmediato. ¿Revocarlo?',
    'You have no tokens yet.' => 'Todavía no tienes tokens.',
    'Generate a token' => 'Generar un token',
    'Treat the token as a password: whoever has it acts as you. You can have as many as you need and revoke each one by itself.' => 'Trata el token como una contraseña: quien lo tenga actúa como tú. Puedes tener los que necesites y revocar cada uno por separado.',
    'Code of the second factor (if you use one)' => 'Código del segundo factor (si usas uno)',
    'Your token' => 'Tu token',
    'Copy it now: it is shown only once. Treat it as a password, whoever has it acts as you.' => 'Cópialo ahora: se muestra una sola vez. Trátalo como una contraseña, quien lo tenga actúa como tú.',
    'Token' => 'Token',
    'Send it in the header of each request:' => 'Envíalo en la cabecera de cada solicitud:',
    'Back to the profile' => 'Volver al perfil',
    'The token was revoked.' => 'El token fue revocado.',

    // Fields of the profile.
    'Identity' => 'Identidad',
    'Name' => 'Nombre',
    'Email' => 'Correo',
    'Email verified' => 'Correo verificado',
    'Language' => 'Idioma',
    'Roles' => 'Roles',
    'Session name' => 'Nombre de la sesión',
    'Session identifier (start)' => 'Identificador de la sesión (inicio)',
    'Session lifetime (seconds)' => 'Duración de la sesión (segundos)',
    'Cookie lifetime (seconds)' => 'Duración de la cookie (segundos)',
    'Cookie path' => 'Ruta de la cookie',
    'Cookie domain' => 'Dominio de la cookie',
    'Cookie secure' => 'Cookie segura',
    'Cookie HTTP only' => 'Cookie solo HTTP',
    'Cookie same site' => 'Cookie del mismo sitio',

    // Data of the session of Keycloak.
    'Realm' => 'Realm',
    'Keycloak token' => 'Token de Keycloak',
    'Issued at' => 'Emitido',
    'Access token expires' => 'El token de acceso vence',
    'Refresh token expires' => 'El token de renovación vence',
    'Authenticated at' => 'Autenticado',
    'Session identifier' => 'Identificador de la sesión',
    'Authentication level' => 'Nivel de autenticación',
    'Client' => 'Cliente',
    'Scope' => 'Alcance',
    'Session in Keycloak' => 'Sesión en Keycloak',
    'Started' => 'Iniciada',
    'Last access' => 'Último acceso',
];
