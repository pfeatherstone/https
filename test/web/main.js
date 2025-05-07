var app = angular.module('testApp', ['ui.bootstrap']);

app.controller('testCtrl', function($scope, $http, $interval, $q) {

    $scope.httpmessage  = "";
    $scope.wsmessage    = "";

    // HTTP
    getStatus = function() {
        $http.post("/darcy", angular.copy($scope.httpmessage))
        .then(function success(response) {
            $scope.httpmessage = response.data;
        }, function myError(response) {
            console.log(response.statusText);
        });
    };

    getStatus();
    $interval(getStatus, 1000);

    // WS
    var socket  = new WebSocket('ws://' + window.location.hostname + ':' + window.location.port + '/ws');
    var promise = null;

    socket.onopen = function(event) {
        console.log("connection opened");

        promise = $interval(function() {
            socket.send("Sending message to server on WS");
        }, 1000);
    };

    socket.onclose = function(event) {
        console.log("connection closed");
        $interval.cancel(promise);
    };

    socket.onerror = function(event) {
        console.log("connection error " + event);
    };

    socket.onmessage = function(event) {
        console.log("Received data");
        $scope.wsmessage = event.data;
        $scope.$apply();
    };
})