<?php
define('IN_PHPBB', true);
$phpbb_root_path = (defined('PHPBB_ROOT_PATH')) ? PHPBB_ROOT_PATH : './';
$phpEx = substr(strrchr(__FILE__, '.'), 1);
include($phpbb_root_path . 'common.' . $phpEx);

// Start session management
$user->session_begin();
$auth->acl($user->data);
$user->setup();

page_header('Reset Password');

$key	= request_var('k', '', true);
$user_id	= request_var('u', '', true);
$submit		= (isset($_POST['submit'])) ? true : false;

function key_valid($key, $user_id)
{
  global $db, $cache, $config;

  if (strlen($key) < 1 || !is_numeric($user_id))
    return false;

    $sql = 'SELECT COUNT(*) AS key_count
      FROM ' . USERS_TABLE . '
      WHERE user_actkey = "' . $db->sql_escape($key) . '" AND user_id = ' . $db->sql_escape($user_id);
    $result = $db->sql_query($sql);
    $key_valid = (int) $db->sql_fetchfield('key_count');
    $db->sql_freeresult($result);

  return ($key_valid > 0 ? true : false);

}

if ($submit)
{
  if (key_valid($key, $user_id))
  {
    $new_password = request_var('new_password', '', true);
    $password_confirm = request_var('password_confirm', '', true);

    if ($new_password == $password_confirm)
    {
      $sql = "UPDATE " . USERS_TABLE . " SET user_password = '" . $db->sql_escape(phpbb_hash($new_password . md5($user_id))) . "', user_actkey = '' WHERE user_actkey = '" . $db->sql_escape($key) . "' AND user_id = " . $db->sql_escape($user_id);
      $db->sql_query($sql);

      $template->assign_vars(array(
  			'S_RESET_RESPONSE'	=> 'SUCCESS',
        'S_RESET_SHOW_FORM' => false
  		));
    }
    else
    {
      $template->assign_vars(array(
  			'S_RESET_RESPONSE'	=> 'PASSWORD_MISSMATCH',
        'S_RESET_SHOW_FORM' => true
  		));
    }

  }
  else
  {
    $template->assign_vars(array(
      'S_RESET_RESPONSE'	=> 'INVALID_KEY',
      'S_RESET_SHOW_FORM' => false
    ));
  }
}
else if (isset($key))
{
  if (key_valid($key, $user_id))
  {
    $template->assign_vars(array(
      'S_RESET_SHOW_FORM' => true,
      'S_RESET_RESPONSE' => 'SHOW_FORM',
			'S_RESET_ACTION'	=> append_sid($phpbb_root_path . 'resetpassword.' . $phpEx, 'k=' . $key . '&u=' . $user_id)
		));

  }
  else
  {
    $template->assign_vars(array(
      'S_RESET_RESPONSE'	=> 'INVALID_KEY',
      'S_RESET_SHOW_FORM' => false
    ));
  }

}
else
{
  $template->assign_vars(array(
    'S_RESET_RESPONSE'	=> 'INVALID_KEY',
    'S_RESET_SHOW_FORM' => false
  ));
}

$template->set_filenames(array(
    'body' => 'resetpassword.html',
));

make_jumpbox(append_sid("{$phpbb_root_path}viewforum.$phpEx"));
page_footer();
?>
