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
    'The user is not authorized to access this resource.' => 'El usuario no está autorizado para acceder a este recurso.',

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
];
