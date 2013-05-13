<?php
/**
 * Google Glass API Functions
 *
 * @author nickmoline
 * @version 0.1
 * @since 0.1
 * @package glasseye
 * @subpackage googleglass
 */

require_once 'google-api-php-client/src/Google_Client.php';
require_once 'google-api-php-client/src/contrib/Google_MirrorService.php';
require_once 'google-api-php-client/src/contrib/Google_PlusService.php';


/**
 * Returns Google API Client object
 *
 * @author nickmoline
 * @version 0.1
 * @since 0.1
 * @param string $access_token Access token to check
 * @param bool $new Create a new client
 * @return obj client object
 */
function get_gclient($access_token = null, $new = false) {
	global $client;

	if (!$client || $new) {
		$client = new Google_Client();
		$client->setApplicationName(APPLICATION_NAME);
		$client->setClientId(API_CLIENT_ID);
		$client->setClientSecret(API_CLIENT_SECRET);
		$client->setDeveloperKey(API_SIMPLE_KEY);

		$client->setRedirectUri(SERVICE_BASE_URL);
		$client->setScopes(
			array(
				'https://www.googleapis.com/auth/glass.timeline',
				'https://www.googleapis.com/auth/plus.me'
			)
		);
	}

	if ($access_token) {
		$client->setAccessToken($access_token);
	}

	return $client;
}

/**
 * Returns Google Glass object
 *
 * @author nickmoline
 * @version 0.1
 * @since 0.1
 * @return obj glass object
 */
function get_glass($access_token = null) {
	global $glass;

	if (!$glass) {
		$glass = new Google_MirrorService(get_gclient($access_token));
	}

	return $glass;
}

/**
 * Returns Google Plus object
 *
 * @author nickmoline
 * @version 0.1
 * @since 0.1
 * @return obj plus object
 */
function get_plus($access_token = null) {
	global $plus;

	if (!$plus) {
		$plus = new Google_PlusService(get_gclient($access_token));
	}
}


/**
 * Raw Insert into Timeline Function
 *
 * @author nickmoline
 * @since 0.1
 * @version 0.1
 * @param string $text HTML/Text Message
 * @param array $menu_items Array of Menu Items
 * @param string $access_token Access Token for sending
 * @param string $bundle_id ID To Thread message with
 * @param bool $is_html [Default true] Content is html
 * @param bool $read_aloud [Default true] Allow Read Aloud option
 * @param bool $audio_notification [Default false] Send an audible ding
 * @param string $spoken_text [optional] Optional different version for spoken text
 * @param string $contentType [optional] MIME Type of optional file attachment
 * @param string $attachment [optional] File Attachment Contents for file attachment.
 * @return obj TimeLine Item
 */
function insertTimelineItem($text, $menu_items = array(), $access_token = null, $bundle_id = null, $is_html = true, $read_aloud = true, $reply = false, $audio_notification = false, $spoken_text = null, $contentType = null, $attachment = null) {
	$timelineItem = new Google_TimelineItem();

	if ($is_html) {
		$timelineItem->setHtml($text);
		if (!$spoken_text) $spoken_text = strip_tags($text);
	} else {
		$timelineItem->setText($text);
		if (!$spoken_text) $spoken_text = strip_tags($text);
	}
	
	if ($reply) {
		$menuItem = new Google_MenuItem();
		$menuItem->setAction("REPLY");
		if (!is_array($menu_items)) { $menu_items = array(); }
		array_push($menu_items, $menuItem);
	}

	if ($read_aloud) {
		$menuItem = new Google_MenuItem();
		$menuItem->setAction("READ_ALOUD");
		array_push($menu_items, $menuItem);
		$timelineItem->setSpeakableText($spoken_text);
	}

	if ($bundle_id) $timelineItem->setBundleId($bundle_id);

	$timelineItem->setMenuItems($menu_items);

	/* if ($audio_notification) {
	 	$notification = new Google_NotificationConfig();
		$notification->setLevel($notificationLevel);
	 	$timelineItem->setNotification($notification);
	} */
	$optParams = array();
	if ($contentType != null && $attachment != null) {
		$optParams['data'] = $attachment;
		$optParams['mimeType'] = $contentType;
	}
	$glass = get_glass($access_token);
	return $glass->timeline->insert($timelineItem, $optParams);
}

function login_user() {
	session_start();
	$token = null;

	global $plus;
	global $glass;
	global $client;

	$client = get_gclient(null,true);
	$plus = new Google_PlusService($client);
	$glass = new Google_MirrorService($client);
	if (array_key_exists('token',$_SESSION)) {
		$token = $_SESSION['token'];
		$client->setAccessToken($token);
	} elseif (array_key_exists('code',$_GET)) {
		$client->authenticate();
		$token = $client->getAccessToken();
		$_SESSION['token'] = $token;
		$client->setAccessToken($token);
	}

	if (!$token) {
		header('Location: ' . $client->createAuthUrl());
		die();
	}

	$profile = $plus->people->get("me");

	$plus_id = $profile['id'];
	$plus_name = $profile['displayName'];

	save_userinfo($token, $plus_id, $plus_name);
	return $token;
}

function save_userinfo($token, $plus_id, $plus_name) {
	global $db;
	
	$existing_user = get_user_by_plusid($plus_id);

	if ($existing_user) {
		$stmt = $db->prepare(
			"UPDATE users u
				SET 
					u.user_name = :username,
					u.user_token = :usertoken,
					u.user_plus_id = :userplusid
				WHERE
					u.user_id = :existinguid"
		);
		$stmt->bindValue(":existinguid",	$existing_user['user_id'],	PDO::PARAM_INT);
		$stmt->bindValue(":username",		$plus_name,					PDO::PARAM_STR);
		$stmt->bindValue(":usertoken",		$token,						PDO::PARAM_STR);
		$stmt->bindValue(":userplusid",		$plus_id,					PDO::PARAM_STR);
		$stmt->execute();
		return $existing_user['user_id'];
	} else {
		$stmt = $db->prepare(
			"INSERT INTO users
				(
					user_name,
					user_token,
					user_plus_id
				)
			VALUES
				(
					:username,
					:usertoken,
					:userplusid
				)"
		);
		$stmt->bindValue(":username",		$plus_name,					PDO::PARAM_STR);
		$stmt->bindValue(":usertoken",		$token,						PDO::PARAM_STR);
		$stmt->bindValue(":userplusid",		$plus_id,					PDO::PARAM_STR);
		$stmt->execute();
		return $db->lastInsertId();
	}	
}

function get_user_by_id($user_id) {
	global $db;

	$stmt = $db->prepare("SELECT * FROM users WHERE user_id = :userid");
	$stmt->bindValue(":userid", $user_id, PDO::PARAM_INT);
	$stmt->execute();
	return $stmt->fetch(PDO::FETCH_ASSOC);	
}

function get_user_by_plusid($plus_id) {
	global $db;

	$stmt = $db->prepare("SELECT * FROM users WHERE user_plus_id = :plusid");
	$stmt->bindValue(":plusid", $plus_id, PDO::PARAM_STR);
	$stmt->execute();
	return $stmt->fetch(PDO::FETCH_ASSOC);
}

function get_user_by_token($token) {
	global $db;

	$stmt = $db->prepare("SELECT * FROM users WHERE user_token = :token");
	$stmt->bindValue(":token", $token, PDO::PARAM_STR);
	$stmt->execute();
	return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Just a couple of functions that help us figure out who is logged in
function getProfile($service, $user_id) {
  return $service->people->get($user_id);
}

function getCurrentProfileId($service) {
  $current_user = getProfile($service, "me");
  return $current_user['id'];
}

function getCurrentProfileName($service) {
	$current_user = getProfile($service, "me");
	return $current_user['name']['formatted'];
}
