<?php

	include_once("include/config.php");
	include_once "lib/lib.php";
	
	header('Access-Control-Allow-Origin: *');
	
	if (empty($_POST)) {
		parse_str(file_get_contents('php://input'), $_POST);
	}
	$dbt = db_conn("traffic");
	
	if (empty($_POST)) {
		die('fail: POST required');
	}
	
	$ip = $_POST['ip'] ?: $_SERVER['REMOTE_ADDR'];
	$dwell = $_POST['dwell'];
	$url = $_POST['url'];
	$urlparts = parse_url($url); 
	$urlparts['port'] or ($urlparts['port'] = '');  // replace any empty port with an empty string
	$urlparts['path'] or ($urlparts['path'] = '/');  // replace any empty path with a single slash
	$urlparts['query'] and ($urlparts['query'] = '?'.$urlparts['query']);  // prefix any non-empty querystring with a question mark
	$urlparts['query'] or ($urlparts['query'] = '');  // replace any missing querystring with an empty string
    $ip_split = explode('.', $ip);
    $hexip = sprintf('%02x%02x%02x%02x', $ip_split[0], $ip_split[1], $ip_split[2], $ip_split[3]);
	
	$agent = $_SERVER['HTTP_USER_AGENT'];
	$start = $_POST['start'];
	$pnow = $_POST['pnow'];
	$timing = $_POST['timing'];
	
	$q = "INSERT INTO durations (ip_id, dwell_time, domain, url_id, user_agent, start, pnow, timing) VALUES
		(log_getipid(:hexip, 0), (:dwell || ' SECONDS')::INTERVAL, :domain, log_geturlid(:protocol, :domain, :port, :path, :query), 
		:agent, :start, :pnow, :timing)";
	$stmt = $dbt->prepare($q);
	$stmt->bindParam(':hexip', $hexip);
	$stmt->bindParam(':dwell', $dwell);
	$stmt->bindParam(':protocol', $urlparts['scheme']);
	$stmt->bindParam(':domain', $urlparts['host']);
	$stmt->bindParam(':port', $urlparts['port']);
	$stmt->bindParam(':path', $urlparts['path']);
	$stmt->bindParam(':query', $urlparts['query']);
	
	$stmt->bindParam(':agent', $agent);
	$stmt->bindParam(':start', $start);
	$stmt->bindParam(':pnow', $pnow);
	$stmt->bindParam(':timing', $timing);
	if ($stmt->execute() && $stmt->rowCount()) {
		echo 'success';
	} else {
		echo 'fail';
	}
