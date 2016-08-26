(function(){

	angular.module('irma')
  .controller('StatsCtrl', ['$scope','$log', 'bridge', function ($scope, $log, bridge) {

  		//var vm = this;

  		$scope.labels = ["Infected", "Clean", "Errors"];
    	//$scope.data = [300, 500, 100];

    	$scope.avstats = [];


    	// Extension function with parameters.
  		$scope.get_stats_ex = function(av, type, name, tags){

  		};

  		// get statistics.
  		$scope.get_stats = function(){

  			var url = '/stats';

  			$log.debug('get_stats :: function entry...');

  			return bridge.get({url: url}).then(statComplete);

        function statComplete(response) {

          $log.debug('get_stats :: response = ', response);
          $scope.avstats = response.items;

          for (var i = $scope.avstats.length - 1; i >= 0; i--) {
            name = $scope.avstats[i].name;
            $log.debug('statComplete :: avname = ', name);

            var inf = $scope.avstats[i].infected;
            var clean = $scope.avstats[i].clean;
            var err = $scope.avstats[i].errors;

            $scope.avstats[i].data = [inf,clean,err];

          }


          $log.debug('statComplete :: avstats = ', $scope.avstats);

          return response;
        }

  			

  		};

  		// call function
  		$scope.get_stats();


   }]);



}) ();


