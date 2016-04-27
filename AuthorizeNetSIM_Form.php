<?php

namespace ramzyvirani\Authorizenet;

class AuthorizeNetSIM_Form extends \AuthorizeNetSIM_Form
{
    /**
     * Generates a fingerprint needed for a hosted order form or DPM.
     *
     * @param string $api_login_id    Login ID.
     * @param string $transaction_key API key.
     * @param string $amount          Amount of transaction.
     * @param string $fp_sequence     An invoice number or random number.
     * @param string $fp_timestamp    Timestamp.
     * @param string $fp_currency_code    Currency Code.
     *
     * @return string The fingerprint.
     */
    public static function getFingerprint($api_login_id, $transaction_key, $amount, $fp_sequence, $fp_timestamp, $fp_currency_code=null)
    {
        $api_login_id = ($api_login_id ? $api_login_id : (defined('AUTHORIZENET_API_LOGIN_ID') ? AUTHORIZENET_API_LOGIN_ID : ""));
        $transaction_key = ($transaction_key ? $transaction_key : (defined('AUTHORIZENET_TRANSACTION_KEY') ? AUTHORIZENET_TRANSACTION_KEY : ""));
        $currency_code = (!is_null($fp_currency_code)) ? $fp_currency_code : "";
        if (function_exists('hash_hmac')) {
            return hash_hmac("md5", $api_login_id . "^" . $fp_sequence . "^" . $fp_timestamp . "^" . $amount . "^" . $currency_code , $transaction_key);
        }
        return bin2hex(mhash(MHASH_MD5, $api_login_id . "^" . $fp_sequence . "^" . $fp_timestamp . "^" . $amount . "^" . $currency_code, $transaction_key));
    }
}