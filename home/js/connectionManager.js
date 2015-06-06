function ConnectionManager() {

    this.maxRequests = 10; // Max number of open connections allowed.
	this.requestId = 0;	   // To maintain unique id for each request we made.
	this.waitingQueue = []; // To keep track of waiting requests.
	this.pendingCallCount = 0; // To Keep track of requests that are waiting for response
	
	//To set max number of open connections (maxRequests)	
	this.setMaxConnReq = function(value) {
		this.maxRequests = value;
	}
	
	// To ADD requests objects to waitingQueue 
	this.addToWaitingQueue = function(request) {
		var checkStatus = this.checkForExistance(request.callerid, this.waitingQueue);
		if(!checkStatus) {
			this.waitingQueue.push(request);
		}
	};
	
	//Check waitig queue on every response to send any waitning requests if exists in the QUEUE. 
	this.checkWaitingQueue = function() {
		if(this.waitingQueue.length != 0) {
			for( var i = this.pendingCallCount; i < this.maxRequests; i++) {
				var request = this.waitingQueue.shift();
				this.send(request.callerid, request.method, request.url, request.params, request.successCallback, request.errorCallback, request.options);
			}
		}
	}
	// Check the waiting Queue with the callerid if it doen't exist the add request to pending queue otherwise ignore it.
	this.checkForExistance = function(callerid, list) {
		for (var i = 0; i < list.length; i++) {
			if (list[i].callerid === callerid) {
				return true;
			}
		}
		return false;
	}
	
	// This is generic function for all types of send requests.
	this.send = function(callerid, method, url, params, successCallback, errorCallback, options) {
		var me = this;
		var serverCallObject = {
			requestid: me.requestId++,
			callerid: callerid,
			method: method,
			url: url,
			data: params,
			successcallback: successCallback,
			errorcallback: errorCallback,
			failurecallback: $.proxy(this.defaultCallFailureHandler, this),//this.defaultCallFailureHandler,
			async: true
		};
		
		if (typeof options == "object") { // merge/override the serverCallObject with options passed in from the caller.
			$.extend(serverCallObject, options);
		} // else, we ignore the options parameter passed in, and go with our own defaults.
		
		var localSuccessHandler = function(data, textStatus, jqXHR) {
			me.successHandler(serverCallObject, jqXHR, textStatus, data);
		};
		
		var localErrorHandler = function(jqXHR, textStatus, errorThrown) {
			me.errorHandler(serverCallObject, jqXHR, textStatus, errorThrown);
		};
		if ((options) && (options.hasOwnProperty('callbackParameter'))) {
			var ajaxPOptions = {
				type: serverCallObject.method, 
				url: serverCallObject.url,
				data: serverCallObject.data,
				callbackParameter: serverCallObject.callbackParameter,
				success: localSuccessHandler,
				error: localErrorHandler,
				async: serverCallObject.async
			};
			this.pendingCallCount++;
			$.jsonp(ajaxPOptions);
		}else {
			var ajaxOptions = {
				type: serverCallObject.method, 
				url: serverCallObject.url,
				data: serverCallObject.data,
				success: localSuccessHandler,
				error: localErrorHandler,
				async: serverCallObject.async
			};
			this.pendingCallCount++;
			$.ajax(ajaxOptions);
		}
	};
	
	// Local success handler function	
	this.successHandler = function(callObject, jqXHR, textStatus, data) {
		// First things first!
		this.pendingCallCount--;
		callObject.status = textStatus;
		callObject.jqXHR = jqXHR;
		callObject.response = data;
		
		this.processCallResponse(callObject);
	};
	
	// Local error handler function
	this.errorHandler = function(callObject, jqXHR, textStatus, errorThrown) {
		// First things first!
		this.pendingCallCount--;
		callObject.status = textStatus;
		callObject.jqXHR = jqXHR;
		callObject.error = errorThrown;
		
		this.processCallResponse(callObject);
	}
	
	// To check the max parallel connections allowed limit.
	this.checkMaxConnections = function(request) {
		if( this.pendingCallCount < this.maxRequests) {
			this.send(request.callerid, request.method, request.url, request.params, request.successCallback, request.errorCallback, request.options);
		} else {
			this.addToWaitingQueue(request);
		}
	};
	
	// Helper function to make POST AJAX call
	this.sendPost = function (callerid, url, params, successCallback, errorCallback, options) {
		var request = { 
			method: 'POST',
			url: url,
			callerid: callerid,
			errorCallback: errorCallback,
			successCallback: successCallback,
			params: params,
			options: options
		};
		this.checkMaxConnections(request);
	};
	
	//Helper function to make GET AJAX call
	this.sendGet = function (callerid, url, params, successCallback, errorCallback, options) {
		var request = { 
			method: 'GET',
			url: url,
			callerid: callerid,
			errorCallback: errorCallback,
			successCallback: successCallback,
			params: params,
			options: options
		};
		this.checkMaxConnections(request);
	};
	
	//Helper function to make GET JSONP call
	this.sendGetJsonP = function (callerid, url, params, successCallback, errorCallback, options) {
		var request = { 
			method: 'GET',
			url: url,
			callerid: callerid,
			errorCallback: errorCallback,
			successCallback: successCallback,
			params: params,
			options: options
		};
		this.checkMaxConnections(request);
	};
	
	//Helper function to make multiple GET JSONP call
	this.sendMultiGetJsonP = function(callerid, urlsArray, params, successCallback, errorCallback, options) {
		var idIncr = 0;
		var id = callerid;
		var requestArray = $.map(urlsArray, function (url) {
			var	callerid = id+idIncr;
			idIncr++;
		    return { 
				method: 'GET',
				url: url,
				callerid: callerid,
				errorCallback: errorCallback,
				successCallback: successCallback,
				params: params,
				options: options
			};
		});
		
		for( var i = 0; i < requestArray.length; i++) {
			var request = requestArray[i];
			this.checkMaxConnections(request);
		}
	};
	
	this.defaultCallFailureHandler = function(data, status, jqXHR, url) {
		var selfParams = {};
		selfParams = {
			body : "Invalid response from Server",
			message : "Failure getting " + url + "\n" + data.message
		};
		this.serverFailureAlert(selfParams);
	};
	
	this.serverFailureAlert = function(_params) {
		$("<div class='alertmsg'></div>").html(_params.message).dialog();
	};
	
	// To process each call response and trigger respective success/ failure function.
	this.processCallResponse = function(callObject) {
		this.checkWaitingQueue();
		if (callObject.status == "success" || callObject.status == "notmodified") { 
			var data = callObject.response;
			if (data == null) {
				callObject.errorcallback(callObject.jqXHR, "unreachable", "No response from server", callObject.url);
			} else if (callObject.status != "success") {
				callObject.failurecallback(data, callObject.status, callObject.jqXHR, callObject.url, callObject);
			} else {
				callObject.successcallback(data, callObject.status, callObject.jqXHR, callObject.url, callObject);
			}
		} else {
			callObject.errorcallback(callObject.jqXHR, callObject.status, callObject.error, callObject.url, callObject);
		}
		
	};
}