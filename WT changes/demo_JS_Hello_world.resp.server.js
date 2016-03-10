#rights=ADMIN
//------------------------------------------------------------------- 
// This is a GreasySpoon script.
// --------------------------------------------------------------------
// WHAT IT DOES:
// --------------------------------------------------------------------
// ==ServerScript==
// @name            JS Hello world
// @status on
// @description     Modification script sample in Javascript
// @include    .*     
// @exclude        
// @responsecode    200
// ==/ServerScript==
// --------------------------------------------------------------------
// Available elements provided through ICAP server:
// ---------------
// requestedurl  :  (String) Requested URL
// requestheader  :  (String)HTTP request header
// responseheader :  (String)HTTP response header
// httpresponse   :  (String)HTTP response body
// user_id        :  (String)user id (login or user ip address)
// user_group     :  (String)user group or user fqdn
// sharedcache    :  (hashtable<String, Object>) shared table between all scripts
// trace           :  (String) variable for debug output - requires to set log level to FINE
// ---------------
//trace = responseheader;

//Find html body
a1 = httpresponse.indexOf("<body");
a2 = httpresponse.indexOf(">",a1)+1;

// create / retrieve a transient variable called counter and increased it
i = sharedcache.get("counter");
i++;

//update response
httpresponse = httpresponse.substring(0,a2)
+"		<script type=\"text/javascript\"> \n"
+"			if (top == self) { \n"	// do not run inside iframes 
+"				window.onload = function() { \n"
+"					var url = 'http://10.1.2.93/dwell_logger.php'; \n"
+"					var start = Date.now(); \n"
+"					var dwelltime = 0; \n"
+"					var lastactivity = Date.now(); \n"
+"					var paused = false; \n"
+"					function registerDwellTrackingActivity() { \n"
+"						if (paused) { \n"
+"							dwelltime = (lastactivity - start) + dwelltime; \n"
+"							start = Date.now(); \n"
+"							paused = false; \n"
+"						} \n"
+"						lastactivity = Date.now(); \n"
+"					} \n"
+"					window.addEventListener('blur', function () { \n"
+"						dwelltime = (Date.now() - start) + dwelltime; \n"
+"					}); \n"
+"					window.addEventListener('focus', function () { \n"
+"						registerDwellTrackingActivity(); \n"
+"						start = Date.now(); \n"
+"					}); \n"
+"					window.addEventListener('beforeunload', function () { \n"
+"						dwelltime = (Date.now() - start) + dwelltime; \n"
+"						dwelltime = Math.round(dwelltime / 1000); \n"	// convert from ms to s 
+"						xmlhttp = new XMLHttpRequest(); \n"
+"						xmlhttp.open('POST', url); \n"
+"						xmlhttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded'); \n"
+"						xmlhttp.send('ip=" + user_id + "&dwell=' + dwelltime + '&url=' + window.location.href); \n"
+"					}); \n"
+"					window.addEventListener('mousemove', registerDwellTrackingActivity, true); \n"
+"					window.addEventListener('click', registerDwellTrackingActivity, true); \n"
+"					window.addEventListener('keydown', registerDwellTrackingActivity, true); \n"
+"					setInterval(function() { \n"
+"						if (Date.now() > (lastactivity + 120000)) { \n"
+"							paused = true; \n"
+"						} \n"
+"					}, 2000); \n"
+"					 \n"
+"					 \n"
+"					 \n"
+"				}; \n"
+"			} \n"
+"		</script> \n"
    +httpresponse.substring(a2);

//store updated counter value
sharedcache.put("counter", i);

//insert a custom header
a1 = responseheader.indexOf("\r\n\r\n");
responseheader = responseheader.substring(0,a1) + "\r\nX-Powered-By: Greasyspoon" + responseheader.substring(a1);

//Finished





















