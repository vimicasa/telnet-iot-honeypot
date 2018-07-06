 
function extractHash() {
	var table  = {};
	var values = window.location.hash.substr(1);
	values = values.split("&");
	for (var i = 0; i < values.length; i++) {
		var tuple = values[i].split("=");
		var name  = tuple[0];
		var value = tuple.length > 1 ? tuple[1] : null;
		table[name] = value;
	}
	return table;
}

function formatDate(date) {
	d = new Date(date * 1000);
	return d.toTimeString().replace(/.*(\d{2}:\d{2}:\d{2}).*/, "$1");
}

var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"];

function formatDay(date) {
	d = new Date(date * 1000);
	return d.getDate() + " " + months[d.getMonth()];
}

function formatDateTime(date) {
	if (date == null) return "";
	d = new Date(date * 1000);
	return d.getDate() + "." + (d.getMonth()+1) + " " + d.toTimeString().replace(/.*(\d{2}:\d{2}):\d{2}.*/, "$1");
}

function time() {
	return Math.round(new Date().getTime() / 1000);
}

function nicenull (str, el) {
	if (str == null || str == "")
		return el;
	else
		return str;
}

function short (str, l) {
	if (str)
		return str.substring(0, l) + "...";
	else
		return "None";
}

function encurl(url) {
	return btoa(url);
}

function decurl(url) {
	return atob(url);
}

function getHostName(url) {
	var match = url.match(/:\/\/(www[0-9]?\.)?(.[^/:]+)/i);
	if (match != null && match.length > 2 && typeof match[2] === 'string' && match[2].length > 0) {
	return match[2];
	}
	else {
		return null;
	}
}

function getDomain(url) {
	var hostName = getHostName(url);
	var domain = hostName;
	
	if (hostName != null) {
		var parts = hostName.split('.').reverse();
		
		if (parts != null && parts.length > 1 && parts.length != 4) {
			domain = parts[1] + '.' + parts[0];
				
			if (hostName.toLowerCase().indexOf('.co.uk') != -1 && parts.length > 2) {
			  domain = parts[2] + '.' + domain;
			}
		}
	}
	
	return domain;
}
