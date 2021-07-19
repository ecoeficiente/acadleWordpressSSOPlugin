<?php
/**
 * Plugin Name: Acadle SSO
 * Author:      Germán Campos
 * Version: 1.0
 */

if (!defined("ABSPATH"))
{
    exit();
}

define("ACADLE_SSOKEY", "otEAVmDxsfG62XnYZna984zRYIjlUtp6");
define("ACADLE_ACADEMY_URL", "academia.ecoeficiente.es");

add_filter('allowed_redirect_hosts', 'acadle_extend_allowed_domains_list');

function acadle_extend_allowed_domains_list($hosts)
{

    $hosts[] = ACADLE_ACADEMY_URL;

    return $hosts;

}

function acadle_login_redirect($redirect_to, $request, $user)
{
    if (isset($_GET['redirect_url']))
    {
        if (!is_wp_error($user)) return $_GET['redirect_url'] . "?ssoToken=" . getAcadleToken($user);
        else return $_GET['redirect_url'];
    }
    else
    {
        if (!is_wp_error($user) && str_contains($redirect_to, '/sso/authenticate/callback')) return $redirect_to . "?ssoToken=" . getAcadleToken($user);
        else return $redirect_to;
    }
}
add_filter('login_redirect', 'acadle_login_redirect', 10, 3);

define("ACADLE_SSO_PLUGIN_DIR", plugin_dir_path(__FILE__));

require_once ACADLE_SSO_PLUGIN_DIR . "jwt/src/BeforeValidException.php";
require_once ACADLE_SSO_PLUGIN_DIR . "jwt/src/ExpiredException.php";
require_once ACADLE_SSO_PLUGIN_DIR . "jwt/src/SignatureInvalidException.php";
require_once ACADLE_SSO_PLUGIN_DIR . "jwt/src/JWT.php";

use Firebase\JWT\JWT;

function acadleSSO()
{
    if (is_user_logged_in() && !is_admin())
    {
        $academyUserToken = getAcadleToken(wp_get_current_user());
        $url = "https://" . ACADLE_ACADEMY_URL . "/sso/authenticate/callback?ssoToken=" . $academyUserToken;
        wp_redirect($url);
        exit;
    }
}

function getAcadleToken($current_user)
{
    $issuedAt = time();
    $expiresAt = $issuedAt + 30; // Token valid for $tokenDuration seconds
    $userData = ["iat" => $issuedAt, // Required, Token issued at (timestamp)
    "exp" => $expiresAt, // Required, Token expires at (timestamp)
    "firstname" => $current_user->display_name, // Required
    "email" => $current_user->user_email, // Required
    "username" => $current_user->user_login, // Optional, Unique
    ];
    return JWT::encode($userData, ACADLE_SSOKEY, "HS256");
}

