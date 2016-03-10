			if (top == self) { 
				window.onload = function() { 
					var url = 'http://10.1.2.93/dwell_logger.php'; 
					var start = Date.now(); 
					var dwelltime = 0; 
					var lastactivity = Date.now(); 
					var paused = false; 
					function registerDwellTrackingActivity() { 
						if (paused) { 
							dwelltime = (lastactivity - start) + dwelltime; 
							start = Date.now(); 
							paused = false; 
						} 
						lastactivity = Date.now(); 
					} 
					window.addEventListener('blur', function () { 
						dwelltime = (Date.now() - start) + dwelltime; 
					}); 
					window.addEventListener('focus', function () { 
						registerDwellTrackingActivity(); 
						start = Date.now(); 
					}); 
					window.addEventListener('beforeunload', function () { 
						dwelltime = (Date.now() - start) + dwelltime; 	// bug here, what if not focused?
						dwelltime = Math.round(dwelltime / 1000); 	// convert from ms to s 
						xmlhttp = new XMLHttpRequest(); 
						xmlhttp.open('POST', url); 
						xmlhttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded'); 
						xmlhttp.send('ip=" + user_id + "&dwell=' + dwelltime + '&url=' + window.location.href); 
					}); 
					window.addEventListener('mousemove', registerDwellTrackingActivity, true); 
					window.addEventListener('click', registerDwellTrackingActivity, true); 
					window.addEventListener('keydown', registerDwellTrackingActivity, true); 
					setInterval(function() { 
						if (Date.now() > (lastactivity + 120000)) { 
							paused = true; 
						} 
					}, 2000); 
					 
					 
					 
				}; 
			} 
