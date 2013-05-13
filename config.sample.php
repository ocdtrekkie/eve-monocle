<?php
// Copy this file to config.php and fill in the values below to make this work

define('API_CLIENT_ID',		"GOOGLE CLIENT ID");
define('API_CLIENT_SECRET',	"GOOGLE CLIENT SECRET KEY");
define('API_SIMPLE_KEY',	"GOOGLE API SIMPLE KEY");
define('SITE_URL',			"SITE URL");
define('SERVICE_BASE_URL',	SITE_URL);

define('APPLICATION_NAME',	"Spy with my Glass Eye");

define('DB_HOST',		"localhost");
define('DB_USER',		"username");
define('DB_NAME',		"dbname");
define('DB_PASS',		"dbpass");

$api_client_id 			= API_CLIENT_ID;
$api_client_secret 		= API_CLIENT_SECRET;
$api_simple_key 		= API_SIMPLE_KEY;
$service_base_url 		= SERVICE_BASE_URL;

$db = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);

