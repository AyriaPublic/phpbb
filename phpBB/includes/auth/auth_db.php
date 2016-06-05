<?php
/**
* Database auth plug-in for phpBB3
*
* Authentication plug-ins is largely down to Sergey Kanareykin, our thanks to him.
*
* This is for authentication via the integrated user table
*
* @package login
* @version $Id$
* @copyright (c) 2005 phpBB Group
* @license http://opensource.org/licenses/gpl-license.php GNU Public License
*
*/

/**
* @ignore
*/
if (!defined('IN_PHPBB'))
{
	exit;
}

/**
* Login function
*
* @param string $username
* @param string $password
* @param string $ip			IP address the login is taking place from. Used to
*							limit the number of login attempts per IP address.
* @param string $browser	The user agent used to login
* @param string $forwarded_for X_FORWARDED_FOR header sent with login request
* @return array				A associative array of the format
*							array(
*								'status' => status constant
*								'error_msg' => string
*								'user_row' => array
*							)
*/
function login_db($username, $password, $ip = '', $browser = '', $forwarded_for = '')
{
	global $db, $config;

	// do not allow empty password
	if (!$password)
	{
		return array(
			'status'	=> LOGIN_ERROR_PASSWORD,
			'error_msg'	=> 'NO_PASSWORD_SUPPLIED',
			'user_row'	=> array('user_id' => ANONYMOUS),
		);
	}

	if (!$username)
	{
		return array(
			'status'	=> LOGIN_ERROR_USERNAME,
			'error_msg'	=> 'LOGIN_ERROR_USERNAME',
			'user_row'	=> array('user_id' => ANONYMOUS),
		);
	}

	$username_clean = utf8_clean_string($username);

	$sql = 'SELECT user_id, username, user_password, user_passchg, user_pass_convert, user_email, user_type, user_login_attempts
		FROM ' . USERS_TABLE . "
		WHERE username_clean = '" . $db->sql_escape($username_clean) . "'";
	$result = $db->sql_query($sql);
	$row = $db->sql_fetchrow($result);
	$db->sql_freeresult($result);


	if (($ip && !$config['ip_login_limit_use_forwarded']) ||
		($forwarded_for && $config['ip_login_limit_use_forwarded']))
	{
		$sql = 'SELECT COUNT(*) AS attempts
			FROM ' . LOGIN_ATTEMPT_TABLE . '
			WHERE attempt_time > ' . (time() - (int) $config['ip_login_limit_time']);
		if ($config['ip_login_limit_use_forwarded'])
		{
			$sql .= " AND attempt_forwarded_for = '" . $db->sql_escape($forwarded_for) . "'";
		}
		else
		{
			$sql .= " AND attempt_ip = '" . $db->sql_escape($ip) . "' ";
		}

		$result = $db->sql_query($sql);
		$attempts = (int) $db->sql_fetchfield('attempts');
		$db->sql_freeresult($result);

		$attempt_data = array(
			'attempt_ip'			=> $ip,
			'attempt_browser'		=> trim(substr($browser, 0, 149)),
			'attempt_forwarded_for'	=> $forwarded_for,
			'attempt_time'			=> time(),
			'user_id'				=> ($row) ? (int) $row['user_id'] : 0,
			'username'				=> $username,
			'username_clean'		=> $username_clean,
		);
		$sql = 'INSERT INTO ' . LOGIN_ATTEMPT_TABLE . $db->sql_build_array('INSERT', $attempt_data);
		$result = $db->sql_query($sql);
	}
	else
	{
		$attempts = 0;
	}

	if (!$row)
	{
		if ($config['ip_login_limit_max'] && $attempts >= $config['ip_login_limit_max'])
		{
			return array(
				'status'		=> LOGIN_ERROR_ATTEMPTS,
				'error_msg'		=> 'LOGIN_ERROR_ATTEMPTS',
				'user_row'		=> array('user_id' => ANONYMOUS),
			);
		}

		return array(
			'status'	=> LOGIN_ERROR_USERNAME,
			'error_msg'	=> 'LOGIN_ERROR_USERNAME',
			'user_row'	=> array('user_id' => ANONYMOUS),
		);
	}

	$show_captcha = ($config['max_login_attempts'] && $row['user_login_attempts'] >= $config['max_login_attempts']) ||
		($config['ip_login_limit_max'] && $attempts >= $config['ip_login_limit_max']);

	// If there are too much login attempts, we need to check for an confirm image
	// Every auth module is able to define what to do by itself...
	if ($show_captcha)
	{
		// Visual Confirmation handling
		if (!class_exists('phpbb_captcha_factory'))
		{
			global $phpbb_root_path, $phpEx;
			include ($phpbb_root_path . 'includes/captcha/captcha_factory.' . $phpEx);
		}

		$captcha =& phpbb_captcha_factory::get_instance($config['captcha_plugin']);
		$captcha->init(CONFIRM_LOGIN);
		$vc_response = $captcha->validate($row);
		if ($vc_response)
		{
			return array(
				'status'		=> LOGIN_ERROR_ATTEMPTS,
				'error_msg'		=> 'LOGIN_ERROR_ATTEMPTS',
				'user_row'		=> $row,
			);
		}
		else
		{
			$captcha->reset();
		}

	}

	// Check password ...
	if (phpbb_check_hash( ($password . md5($row['user_id'])), $row['user_password']))
	{

		$sql = 'DELETE FROM ' . LOGIN_ATTEMPT_TABLE . '
			WHERE user_id = ' . $row['user_id'];
		$db->sql_query($sql);

		if ($row['user_login_attempts'] != 0)
		{
			// Successful, reset login attempts (the user passed all stages)
			$sql = 'UPDATE ' . USERS_TABLE . '
				SET user_login_attempts = 0
				WHERE user_id = ' . $row['user_id'];
			$db->sql_query($sql);
		}

		// User inactive...
		if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
		{
			return array(
				'status'		=> LOGIN_ERROR_ACTIVE,
				'error_msg'		=> 'ACTIVE_ERROR',
				'user_row'		=> $row,
			);
		}

		// Successful login... set user_login_attempts to zero...
		return array(
			'status'		=> LOGIN_SUCCESS,
			'error_msg'		=> false,
			'user_row'		=> $row,
		);
	}

	// Password incorrect - increase login attempts
	$sql = 'UPDATE ' . USERS_TABLE . '
		SET user_login_attempts = user_login_attempts + 1
		WHERE user_id = ' . (int) $row['user_id'] . '
			AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
	$db->sql_query($sql);

	// Give status about wrong password...
	return array(
		'status'		=> ($show_captcha) ? LOGIN_ERROR_ATTEMPTS : LOGIN_ERROR_PASSWORD,
		'error_msg'		=> ($show_captcha) ? 'LOGIN_ERROR_ATTEMPTS' : 'LOGIN_ERROR_PASSWORD',
		'user_row'		=> $row,
	);

}

?>
