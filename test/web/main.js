var app = angular.module('testApp', ['ui.bootstrap']);

app.controller('testCtrl', function($scope, $http, $interval, $q) {

    $scope.httpmessage = "";

    // API
    getStatus = function() {
        $http.post("/darcy", angular.copy($scope.httpmessage))
        .then(function success(response) {
            $scope.httpmessage = response.data;
        }, function myError(response) {
            console.log(response.statusText);
        });
    };

    getStatus(true);
    $interval(getStatus, 1000);
})