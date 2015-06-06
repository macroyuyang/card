$(function(){
	var globalRef = this;
	var assocList = {};
	var urls = [];
	var pages = {};
	var clusterData = {};
	var username;
	var password;
	var maxConnections;
	var pollInterval;
	var addTabFlag = false;
	var pageCount = 0;
	var clusterConatinerHeight = 0;
	var clusterConatinerWidth = 0; 
	var reqManager; 
	var CSRFToken;
	var allowAutoLogin;
	
	$( document ).ready(function() {
		var hiddenForm = $("#hiddenFormClick");
		var auto = hiddenForm.attr("auto");
		reqManager = new ConnectionManager();
		if(auto == 'false') {
			positinLoginView();
			registerLoginClicks();
			checkRemeberMeStatus();
		} else {
			getAutoLogin();
		}
		$(".link").click(function(e) {
			handleLinkClick(e);
		});
	});
	
	//To set delay 
	var delay = (function(){
	  var timer = 0;
	  return function(callback, ms){
		clearTimeout (timer);
		timer = setTimeout(callback, ms);
	  };
	})();
	
	//To handle window resize event
	$(window).resize(function() {
		delay(function(){
		var loginViewStatus = $("#loginView").is(':visible');
		var landingPageViewStatus = $("#landingPageView").is(':visible');
		if(landingPageViewStatus) {
			rePositonClusterView();
		} else {
			rePositionLoginView();
		}
		}, 100);
	});

	//To handle link button click event
	function handleLinkClick(event) {
		var linkLabel = event.currentTarget.id;
		var url;
		switch(linkLabel) {
			case 'pivotal' :
				url = "http://www.gopivotal.com/";
				window.open(url, '_blank');
				break;
			case 'support' :
				url = "https://support.gopivotal.com/hc/en-us";
				window.open(url, '_blank');
				break;
			case 'feedback' :
				url = "http://www.gopivotal.com/contact";
				window.open(url, '_blank');
				break;
			case 'help' :
				url = "../../static/docs/gpdb_only/index.html";
				window.open(url, '_blank');
				break;
			case 'logout' :
				logoutClick();
				break;
		}
	}

	//To check required field validation to enable login button
	function checkrequiredFields() {
		var loginBtn = $("#loginBtn");
		if(($("#userName").val() != '') && ($("#password").val() != '')){
			loginBtn.removeAttr('disabled');
			loginBtn.addClass('greenButton');
		} else {
			loginBtn.attr('disabled','disabled');
			loginBtn.removeClass('greenButton');
		}
	}
	
	//To check rememberMe checkbox status
	function checkRemeberMeStatus() {
		var user = getRememberMeCookie("remeberMe");
		if(user != "" ) {
			$("#userName").val(user);
			$("#myCheck").selected(true);
		} else {
			$("#myCheck").selected(false);
		}
	}


	function rePositionLoginView() {
		positinLoginView();
	}
	
	function rePositonClusterView() {
		positionClusterView(true);
		registerClicks();
	}
	
	//To handle rememberMe checkbox selection event
	function getRememberMestatus() {
		var selected = document.getElementById("myCheck").checked;
		if(selected) {
			setRemeberMeCookie("remeberMe", username, 1);
		} else {
			setRemeberMeCookie("remeberMe", "", -1);
		}
	}
	
	//To set rememberMe cookie
	function setRemeberMeCookie(cName, cValue, CExdays) {
		var now = new Date();
		now.setTime(now.getTime() + (CExdays*24*60*60*1000));
		var expires = "expires="+now.toGMTString();
		document.cookie = cName + "=" + cValue + "; " + expires;
	}
	
	//To get rememberMe cookie value
	function getRememberMeCookie(cName) {
		var cookieName = cName + "=";
		var cookieString = document.cookie.split(';');
		for(var i=0; i<cookieString.length; i++) {
			var cookieValue = cookieString[i];
			while (cookieValue.charAt(0)==' ') {
				cookieValue = cookieValue.substring(1);
			}
			if (cookieValue.indexOf(cookieName) != -1) {
				return cookieValue.substring(cookieName.length,cookieValue .length);
			}
		}
		return "";
	}
	
	function positinLoginView() {
		var mainContainer = $("#maincontainer");
		var loginpanel = $("#loginView");
		var mainConHeight = mainContainer.outerHeight();
		var mainConWidth = 	mainContainer.outerWidth();
		var loginPanelHeight = loginpanel.outerHeight(); //padding
		var loginPanelWidth = loginpanel.outerWidth();
		var loginPanelPos = loginpanel.position();
		loginpanel.css({ "top":(mainConHeight - loginPanelHeight)/4, "left": (mainConWidth - loginPanelWidth)/2 });
	}

	//To handle login form clicks
	function registerLoginClicks(){
		$("#password").keypress(function(event){
			if(event.which == 13) {
		 		loginClick();
			}
		});
		$("#password").keyup(function(e) {
			checkrequiredFields();
		}); 
		$("#userName").keyup(function(e) {
			checkrequiredFields();
		});
		$("#logon").click(function(e) {
			loginClick();
		});
	}
    
	// To get Cluster info
	function loadClusters(csrf_token) {
		var options = {callbackParameter: 'callback'};
		var callerid = "loadclusters";
		var url = "/clusterinfo?csrf=" + csrf_token;
		reqManager.sendGetJsonP(callerid, url, null, clusterDataHandler, clusterErrorHandler, options);
	}

	function getAutoLogin() {
	   var callerId = "autoLogin";
	   var url = "/autologininfo";
	   reqManager.sendGet(callerId, url, null, autoInfoSuccessHandler, autoInfoErrorHandler, null);
	}
	
	// To handle login click
	function loginClick() {
	   username = $("#userName").val();
	   password = $("#password").val();
	   getRememberMestatus();
	   var params = {"username":username,"password":password};
	   var callerId = "login";
	   var url = "/logon";
	   reqManager.sendPost(callerId, url, params, loginSuccessHandler, loginErrorHandler, null);
	}

	//To handle application rendering upon different screen resolutions
	function handleLayoutHeight(tabFlag) {
		var mainConHeight = $(window).height();
		var headerHeight = $("#titleHeader").outerHeight();
		var tabHolderHeight = 0;
		var pageHolder = 0;
		var innerConHeight = mainConHeight - headerHeight; //10 is the padding of title header
		$("#maincontainer").css("height", mainConHeight +"px");
		$("#innerContainer").css("height", innerConHeight +"px");
		if(tabFlag) {
			tabHolderHeight = $(".tabHolder").outerHeight() + 10;
			pageHolder = innerConHeight - tabHolderHeight - 20; 
		} else {
			tabHolderHeight = 0;
			pageHolder = innerConHeight - tabHolderHeight - 20; 
		}
	    $(".pageHolder").css("height", pageHolder +"px");
	}

	function autoInfoSuccessHandler(data,status,response) {
	   var xml = response.responseText
	   var xmlDoc = $.parseXML( xml );
	   var $xml = $( xmlDoc );
	   if ($xml.find("auto")) {
		CSRFToken = $xml.find("csrf").text();
		username = $xml.find("username").text();
		password = $xml.find("key").text();
		allowAutoLogin = $xml.find("autoLogin").text().toLowerCase();
		$("#greetings").text("Welcome "+username);
		loadClusters(CSRFToken);
		$("#landingPageView").css("display","block");
	   }
	}

	function autoInfoErrorHandler(data,status,response) {
		console.log("Unable to fetch Auto login info");
	}

	//To handle login call response on success
	function loginSuccessHandler(data,status,response) {
	   var xml = response.responseText
	   var xmlDoc = $.parseXML( xml );
	   var $xml = $( xmlDoc );
	   if ($xml.find("status").text() == "SUCCESS") {
		$("#loginStatus").text("");
		CSRFToken = $xml.find("csrf_token").text()
		loadClusters(CSRFToken);
		$("#loginView").css("display","none");
		$("#greetings").text("Welcome "+username);
		$("#landingPageView").css("display","block");
		$("#loginView").text("");
	   } else if(($xml.find("error").text())) {
		  $("#loginStatus").text($xml.find("message").text());
	   }else {
		  $("#loginView").css("display","block");
	   }
	}
	
	//To handle logout call response on success
	function logoutSuccessHandler(data,status,response) {
		var xml = response.responseText;
		var xmlDoc = $.parseXML( xml );
		var $xml = $( xmlDoc );
		var url = "/multiCluster";
		if ($xml.find("status").text() == "SUCCESS") {
			window.open(url, '_self');
		}
	}
	
	function logoutClick() {
	   var callerId = "logoff";
	   var url = "/logoff";
	   reqManager.sendGet(callerId, url, null, logoutSuccessHandler, logoutErrorHandler, null);
	}
	
	//To handle login call response on failure
	function loginErrorHandler(data,status,response){
		console.log("Login Error");
	}
	
	//To handle logout call response on failure
	function logoutErrorHandler(data,status,response){
		console.log("Logout Error");
	}
    
	//To handle response cluster data upon success
	function clusterDataHandler(data) {
		var test = buildClusterLayout(data);
		if(test){
			positionClusterView(false);//if argument value set to false represent normal event. if it set to true represent resize event.
			registerClicks();
			getClusterHealth();
		}
	}
	
	function buildClusterLayout(data) {
		var jsonObj = data;
		var clusterView = $("#clusterView");
		var dupClusters = [];
		var dupClusterLength = 0;
		for (var x in jsonObj) {
			var obj = jsonObj[x];
			if (obj.hasOwnProperty('server')) {
				var serverId = obj.server.replace(/ /g,"").toLowerCase();
				var final = $.extend({}, {
					Status : 'false',
					ClusterId : serverId
				}, obj);
				if (assocList.hasOwnProperty(final.ClusterId)) {
					dupClusters.push(obj.server);
				} else {
					assocList[final.ClusterId] = final;
					var groupid = obj.pagegroup.replace( /\s/g, "");
					groupid = groupid.toLowerCase()
					if (pages.hasOwnProperty(groupid)) {
						pages[groupid].push(obj.server);
					} else {
						pages[groupid] = [];
						pages[groupid].push({group : obj.pagegroup});		
						pages[groupid].push(obj.server); 
						pageCount++;
					}
					var url = "http";
					if(obj.sslEnable == "True") {
					   url = "https";
					}
					url += "://"+final.host+":"+final.port+"/healthinfo?serverName="+final.ClusterId;
					urls.push(url);
				}
			} else if((obj.hasOwnProperty('maxConnection')) && (obj.hasOwnProperty('pollInterval'))) {
				maxConnections = obj.maxConnection;
				pollInterval = obj.pollInterval;
				reqManager.setMaxConnReq(maxConnections);
			} else if(obj.hasOwnProperty('Error')) {
				return loadFileParseError(obj);
			}
		}
		dupClusterLength = dupClusters.length;
		if(dupClusterLength > 0) {
			var msg = '<div class = "dupClusterHeader">Duplicate entries in cluster configuration file with server name :</div><div id="dupClustersList">';
			for(var i = 0; i < dupClusterLength; i++){
				msg += "<li>"+dupClusters[i]+"</li>";
			} 
			msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
			$("#innerContainer").html(msg);
			return false;
		}
		if(pageCount == 0){
			var errorString = 'No GPCC cluster info is available in configuration file to load';
			var divString = '<div class="errorHolder">'+ errorString+' </div>';
			clusterView.append(divString); 
		}else if((pageCount > 1)) {
			var divString = '<div id="tabs"><div class="tabHolder"></div><div class="pageHolder"></div></div>';
			clusterView.append(divString);
			var tabHolder = $(".tabHolder");
			var pageHolder = $(".pageHolder");
			var index = 0;
			addTabFlag = true;
			for (page in pages) {
				var tabId = "tab_"+ page;
				if (index == 0) {
					tabHolder.append('<div class="tabs active" id="'+tabId+'"><div class="notifier"></div>' + pages[page][0].group+ '</div>');
					pageHolder.append('<div class="page" id="'+tabId+'" style="display: block;" ></div>');
				} else {
					tabHolder.append('<div class="tabs" id="'+tabId+'"><div class="notifier"></div>' + pages[page][0].group+ '</div>');
					pageHolder.append('<div class="page" id="'+tabId+'" style="display: none;"></div>');
				}
				index++;
				checkTabLabel(tabId, pages[page][0].group);
			}
		} else {
			var divString = '<div class="pageHolder"></div>';
			clusterView = $("#clusterView")
			clusterView.append(divString);
			addTabFlag = false;
		}
		return true;
	}

	function loadFileParseError(data) {
		var msg, len;
		switch(data.Code) {
			case 'INVS':
				msg = '<div class = "dupClusterHeader"> Inavlid user session - '+data.Message+ '</div><div id="dupClustersList">';
				break;
			case 'FTOP':
				msg = '<div class = "dupClusterHeader"> Fail to open cluster configuration file - '+data.Message+ '</div><div id="dupClustersList">';
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'IVSN':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += "<li>"+data.Data[0]+"</li>";
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'IALF':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += "<li>"+data.Data[0]+"</li>";
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'RFM':
				len = data.Data.length;
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[len-1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				for(var i = 0; i < len - 1; i++){
					msg += "<li>"+data.Data[i]+"</li>";
				}
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'INRF':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[0]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'FPE':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file - '+data.Message+ '</div><div id="dupClustersList">';
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'ISSLF':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += "<li>"+data.Data[0]+"</li>";
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'IVTG':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += "<li>"+data.Data[0]+"</li>";
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
			case 'IVPN':
				msg = '<div class = "dupClusterHeader"> Error in cluster configuration file (line:'+data.Data[1]+ ')- '+data.Message+ '</div><div id="dupClustersList">';
				msg += "<li>"+data.Data[0]+"</li>";
				msg += '</div><div class = "dupClusterHeader">Contact Administrator to fix this issue.</div>';
				break;
		}
		$("#innerContainer").html(msg);
		return false
	}

	function checkTabLabel(tabid, tooltip){
	 	var tabObj = $("#"+tabid);
		var textWidth = tabObj[0].scrollWidth - 24;//padding 2+10+2+10
		var divWidth = tabObj.width();
		if(textWidth > divWidth) {
			tabObj.attr("title",tooltip);
		}
	}


	function positionClusterView(isResize) {
		var clusterViewWidth, clusterWidth, clustersPerRow, noOfClsterRows, clusterView;
		clusterView = $("#clusterView");
		handleLayoutHeight(addTabFlag);
		clusterViewWidth = clusterView.width() - 20; //left and right padding 10px for page holder
		clusterWidth = 215;	//width of the cluster image
		clustersPerRow = Math.floor(clusterViewWidth / clusterWidth);
		for (page in pages) {
			if (clustersPerRow != 0)
				noOfClsterRows = Math.ceil(pages[page].length / clustersPerRow);
			else
				noOfClsterRows = 0;
			if(!isResize)	
				renderPageClusters(page, pages[page].length, clustersPerRow, noOfClsterRows, addTabFlag);
			else
				reloadPageClusters(page, pages[page].length, clustersPerRow, noOfClsterRows, addTabFlag);
		}		
		var width = clusterWidth * clustersPerRow;
		var remaininWidth = clusterViewWidth - width - 10; //right margin 10px for last elemnt in row
		var padding = remaininWidth / 2;
		if (padding) {
			$(".page").css("padding-left", padding + "px");
		}
	}

	function clusterErrorHandler(data, status) {
		$("#loginView").css("display","block");
		$("#landingPageView").css("display","none");
		$("#loginStatus").text(data.message);
	}
	
	function reloadPageClusters(page, noOfClusters, clustersPerRow, noOfClsterRows, addTabFlag) {
		var curRow = 0, curCol = 0;
		var rowId = "row_" + curRow; 
		var clusterContainer = $("#clusterView");
		var pageConatiner;
		var clusterString = '';
		var dataString = '<div  class="clusterRow" id="'+ rowId +'">';
		if(addTabFlag) {
			pageConatiner = $(".pageHolder").find("#tab_"+page);
		} else {
			pageConatiner = $(".pageHolder");
			clusterContainer.css("padding-top", 5 + "px");
		}
		for(var i = 1; i < noOfClusters; i++) {
			var cluster = pages[page][i].replace(/ /g,"").toLowerCase();
			clusterData[cluster] = $("#"+cluster).html();
		}
		pageConatiner.text("");
		for (var j = 1; j < noOfClusters; j++) {
			var clusterId = pages[page][j].replace(/ /g,"").toLowerCase();
			if((curCol < clustersPerRow) && (curCol < noOfClusters)){
				clusterString += '<div class="cluster" id="'+clusterId+'">'+clusterData[clusterId]+'</div>';
				curCol++;
			  }else{
				dataString += clusterString;
				pageConatiner.append(dataString);
				curCol = 0;
				curRow++;
				rowId = "row_" + curRow;
				clusterString = '';
				clusterString += '<div class="cluster" id="'+clusterId+'">'+clusterData[clusterId]+'</div>';
				curCol++;
				dataString = '<div class="clusterRow" id='+ rowId +'>';
			 }
		}
		dataString += clusterString;
		clusterConatinerWidth = clusterContainer.width();
		clusterConatinerHeight = clusterContainer.height();
		pageConatiner.append(dataString);
	}
	
	// To Render clusters in to different tabs based on their group id
	function renderPageClusters(page, noOfClusters, clustersPerRow, noOfClsterRows, addTabFlag) {
	   var curRow = 0, curCol = 0;
	   var rowId = "row_" + curRow; 
	   var clusterContainer = $("#clusterView");
	   var pageConatiner;
	   var clusterString = '';
	   var dataString = '<div  class="clusterRow" id="'+ rowId +'">';
	   if(addTabFlag) {
			pageConatiner = $(".pageHolder").find("#tab_"+page);
	   } else {
			pageConatiner = $(".pageHolder");
			clusterContainer.css("padding-top", 5 + "px");
	   }
	   for(var i = 1; i < noOfClusters; i++) {
			var clusterId = pages[page][i].replace(/ /g,"").toLowerCase();
			var metrics = assocList[clusterId];
			if((curCol < clustersPerRow) && (curCol < noOfClusters)){
				clusterString += '<div class="cluster" id="'+clusterId+'"><div class="cluster-alert"></div><div class="dbName">'+metrics.server+'</div><div class="clusterImage" title = "link"></div> <div id="clusterInfo"></div><div class="spinner" id="'+clusterId+'_spinner"></div></div>';
				curCol++;
			}else{
				dataString += clusterString;
				pageConatiner.append(dataString);
				curCol = 0;
				curRow++;
				rowId = "row_" + curRow;
				clusterString = '';
				clusterString += '<div class="cluster" id="'+clusterId+'"><div class="cluster-alert"></div><div class="dbName">'+metrics.server+'</div><div class="clusterImage" title = "link"></div> <div id="clusterInfo"></div><div class="spinner" id="'+clusterId+'_spinner"></div></div>';
				curCol++;
				dataString = '<div class="clusterRow" id='+ rowId +'>';
			 }
		}
	   dataString += clusterString;
	   clusterConatinerWidth = clusterContainer.width();
	   clusterConatinerHeight = clusterContainer.height();
	   pageConatiner.append(dataString);
	}
	
	function loadClusterDashboard(clusterId) {
			var metrics = assocList[clusterId];
			if((metrics.DbStatus != "UNREACHABLE") && (metrics.DbStatus != "UNSUPPORTED")) {
				var proto = getHttpConnString(metrics);
				var url = proto+"://"+metrics.host+":"+metrics.port;
				if(allowAutoLogin == "true") {
					if(metrics.autologin == "True") {
						if(window.location.protocol == proto+":"){
							var targetId = "theWindow"+clusterId;
							var loginForm = '<form id="hiddenForm" method="post" action="'+url+'" target="'+targetId+'"><input id = "userName" type="hidden" name="username" value="'+username+'"/><input id ="password" type="hidden" name="password" value="'+password+'"/></form>';
							var hiddenFormClick = $('#hiddenFormClick');
							hiddenFormClick.append(loginForm);
							var hiddenForm = hiddenFormClick.find('#hiddenForm');
							window.open('', targetId);
							hiddenForm.submit();
							hiddenFormClick.text("");
						} else {
							window.open(url, '_blank');
						}
					} else {
						window.open(url, '_blank');
					}
				} else {
					window.open(url, '_blank');
				}
			}
	}

	//To register application level clicks
	function registerClicks() {
	   	//To handle click on cluster to redirect to respective GPCC
		$('.cluster').click(function(e){
		    loadClusterDashboard(this.id);
		});
	
		// To handle tab clicks to navigate to different cluster groups.
		$(".tabs").click(function(e) {
			var tabHolder = $(".tabHolder");
			var tabToActivate = tabHolder.find("#"+e.target.id);
			for (var i = 0; i < tabHolder[0].children.length; i++) {
			  var node = tabHolder[0].children[i];
			  if (node.nodeType == 1) { 
				  if(node == tabToActivate[0]) {
				   tabToActivate.addClass("active")
				  } else{
				   $(node).removeClass("active");
				  }
			  }
			}
			var tabCtrl = $(".pageHolder");
			var pageToActivate = tabCtrl.find("#"+e.target.id);
			  for (var i = 0; i < tabCtrl[0].children.length; i++) {
				  var node = tabCtrl[0].children[i];
				  if (node.nodeType == 1) {
					  node.style.display = (node == pageToActivate[0]) ? 'block' : 'none';
				  }
			  }
		});
	}
	
	//To trigger health info calls to remote clusters
	function getClusterHealth() {
		var options = {callbackParameter: 'callback'};
		reqManager.sendMultiGetJsonP("clusterHealth", urls, null, HealthinfoHandler, errorHandler, options);
		setTimeout(function(){ 
			getClusterHealth();
		}, pollInterval);
	}
		    
	//To handle helth information from remote clusters on success. 
	function HealthinfoHandler(data, status, response) {
	   $.each(data, function(key,value){
		 var serverId = value.Server.replace(/ /g,"").toLowerCase();
		 if(assocList.hasOwnProperty(serverId)) {
			 var final = $.extend({}, assocList[serverId], value);
			 assocList[serverId] = final;
			 updateHealthInfo(final);
			}
		});
	}
	
	//To parse date string
	function parseDate(date) {
		var dateString = date.replace(/[A-Za-z]/g, "");
		var parseString = dateString .match(/^\s*([0-9]+)\s*-\s*([0-9]+)\s*-\s*([0-9]+)(.*)$/);
		var formatDate = parseString[2]+"/"+parseString[3]+"/"+parseString[1]+parseString[4];
		return (new Date(formatDate));
	}
	
	function updateHealthInfo(data) {
		var infoStr;
		var imageSrc;
		var clusterId = data.server.replace(/ /g,"").toLowerCase()
		var curDiv = $("#"+clusterId);
		var image = curDiv.find(".clusterImage");
		var clusterInfo = curDiv.find("#clusterInfo");
		var spinner = curDiv.find("#"+clusterId+"_spinner");
		
		if(data.Status) {
			var startTime = parseDate(data.GpdbStartTime);
			var localTime = parseDate(data.LocalServerTime);
			var dayDiff = localTime - startTime;
			var sign = dayDiff < 0 ? -1 : 1;
			var milliseconds = 0, seconds = 0, minutes = 0, hours = 0, days = 0;
			dayDiff /=sign; 
			dayDiff =(dayDiff -(milliseconds=dayDiff %1000))/1000;
			dayDiff =(dayDiff -(seconds = dayDiff % 60))/60;
			dayDiff =(dayDiff -(minutes = dayDiff % 60))/60;
			days=(dayDiff -(hours = dayDiff % 24))/24; 
			var upTime = days+'d ' +hours+'h '+minutes+'m '
			infoStr ='<div class="labelHolder">Uptime:</div><div class="dataHolder">'+upTime+'</div><div class="labelHolder">GPDB Version:</div><div class="dataHolder">'+data.GpdbVersion+'</div><div class="labelHolder">Connections:</div><div class="dataHolder">'+data.NumOpenConnections+'</div><div class="labelHolder">Active Queries:</div><div class="dataHolder">'+data.ActiveQueries+'</div>';
		} else {
			infoStr ='<div class="labelHolder">Uptime:</div><div class="dataHolder">-</div><div class="labelHolder">GPDB Version:</div><div class="dataHolder">-</div><div class="labelHolder">Connections:</div><div class="dataHolder">-</div><div class="labelHolder">Active Queries:</div><div class="dataHolder">-</div>';
		}
		image.attr("title","link");
		switch(data.DbStatus) {
			case 'NORMAL' :
						imageSrc = '../home/assets/images/Normal.png';
						break;
			case 'DOWN' :
						imageSrc = '../home/assets/images/Down.png';
						break;
			case 'CRITICAL' :
						imageSrc = '../home/assets/images/Critical.png';
						break;
			case 'UNREACHABLE' :
						imageSrc = '../home/assets/images/Unreachable.png';
						image.removeAttr("title");
						image.css('cursor','default');
						break;
			case 'DEGRADED' :
						imageSrc = '../home/assets/images/Degraded.png';
						break;
			case 'UNBALENCED' :
						imageSrc = '../home/assets/images/Unbalenced.png';
						break;
			case 'UNSUPPORTED' :
						imageSrc = '../home/assets/images/Unsupported.png';
						break;
			default :
						imageSrc = '../home/assets/images/Unreachable.png';
		}

		checkDownCount();		
		spinner.css("display","block");
		clusterInfo.text("");
		image.css('background-image', 'url(' + imageSrc + ')');
		clusterInfo.append(infoStr);
		spinner.css("display","none");		
	}

    // To handle failure response of health info call
	function errorHandler(data) {
		var server = data.url.split("=")[1];
		if(assocList.hasOwnProperty(server)) {
			var metric = assocList[server];
			if(window.location.protocol == data.url.split(":")[0]+":"){
				var url = "/getStatus";
				var serverURL = getHttpConnString(metric);
				serverURL += "://"+metric.host+":"+metric.port+"/healthinfo"
				var params = {"server":server,"url":serverURL};
				var callerId = server+"_getstatus";
				reqManager.sendPost(callerId, url, params, getStatusSuccessHandler, getStatusErrorHandler, null);
			} else {
				var final = $.extend({}, assocList[server], {DbStatus :"UNREACHiABLE",Status:false});
				var alertObj = $("#"+server).find(".cluster-alert");
				assocList[server] = final;
				updateHealthInfo(final);
				alertObj.text("!");
				alertObj.addClass("alertNotifier");
				alertObj.attr("title","This cluster requesting to load HTTP content from secured tunnel:Mixed content prasent. To allow access disable protection for this multiCluster site.");
			}
		}
	}

	function getHttpConnString(metric) {
		var httpString = "http";
		if(metric.sslEnable == "True") {
			httpString = "https";
		}
		return httpString; 
       }

	function getStatusSuccessHandler(data, status, response, url, callObj) {
		var xml = response.responseText;
	   	var xmlDoc = $.parseXML(xml);
	   	var $xml = $(xmlDoc);
		var supportedVersion = false;
		var server = callObj.data.server;
		var data = $xml.find("error");
		if(data) {
			var code = $xml.find("code").text();
			if(code == 'BAD_REQUEST') {
				var final = $.extend({}, assocList[server], {DbStatus :"UNSUPPORTED",Status:false});
				assocList[server] = final;
				removeFromURLsList(server);
				updateHealthInfo(final);
			} else if(code == 'UNREACHABLE') {
				var final = $.extend({}, assocList[server], {DbStatus :"UNREACHABLE",Status:false});
				assocList[callObj.data.server] = final;
				updateHealthInfo(final);
			} else if(code == 'INTERNAL') {
				 var final = $.extend({}, assocList[server], {DbStatus :"UNREACHABLE",Status:false});
				assocList[callObj.data.server] = final;
				updateHealthInfo(final);
			}
		}
	}

	function getStatusErrorHandler(data, status, response, url, callObj) {
		var server = callObj.data.server;
		var final = $.extend({}, assocList[server], {DbStatus :"UNREACHABLE",Status:false});
		assocList[callObj.data.server] = final;
		updateHealthInfo(final);
	}

	function removeFromURLsList(serverid) {
		for (var i = 0; i < urls.length; i++) {
			var server = urls[i].split("=")[1];
			if(server == serverid) {
				urls.splice(i, 1);
				break;
			}
		}
	}

	function checkDownCount() {
		if(pageCount > 1) {
			for (page in pages) {
				var downCount = checkTabDownCount(pages[page], pages[page].length);
				var tabObj = $("#tab_"+ page);
				var obj = tabObj.find(".notifier");

				if(downCount > 0) {
					var offset = tabObj.offset();
					var left = offset.left + tabObj.width() + 10 - 5; //padding 10px
					var top = offset.top + tabObj.height() - 25;
					obj.addClass('clusterNotifier');
					obj.offset({ top: top, left: left})
					obj.text(downCount);
				} else {
					obj.text("");
					obj.removeClass('clusterNotifier');
				}
			}		
		}
	}

	function checkTabDownCount(tabData, len) {
		var count = 0;
		for(var key = 1; key < len; key++) {
			var clusterData = assocList[tabData[key].replace(/ /g,"").toLowerCase()];
			if( clusterData.DbStatus == 'DOWN') {
				count++;
			} 
		}
		return count;
	}

});
