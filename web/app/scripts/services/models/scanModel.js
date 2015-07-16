(function () {
  'use strict';

  angular
    .module('irma')
    .factory('scanModel', Scan);

  Scan.$inject = ['$rootScope', '$fileUploader', '$timeout', '$log', 'api', 'alerts', 'constants'];

  function Scan($rootScope, $fileUploader, $timeout, $log, api, alerts, constants) {
    function ScanModel(id) {
      this.id = id;
      this.state = undefined;
      this.api = api;
      this.task = undefined;
      this.base = undefined;
      this.uploader = $fileUploader.create();
      this.status = constants.scanStatusCodes.STOPPED;
      this.results = undefined;
      this.scanProgress = {
        progress: 0,
        total: 0,
        successful: 0,
        finished: 0
      };

      // Bind uploader events
      this.uploader.bind('error',          this.errorUpload.bind(this));
      this.uploader.bind('completeall',    this.doneUpload.bind(this));
      this.uploader.bind('afteraddingall', this.fileAdded.bind(this));
    }

    ScanModel.prototype = {
      setState: setState,
      hasFiles: hasFiles,
      getPopover: getPopover,
      startUpload: startUpload,
      cancelUpload: cancelUpload,
      errorUpload: errorUpload,
      doneUpload: doneUpload,
      startScan: startScan,
      cancelScan: cancelScan,
      updateScan: updateScan,
      setProgress: setProgress,
      getResults: getResults,
      getResult: getResult,
      fileAdded: fileAdded
    };

    return ScanModel;

    // Functions binded to ScanModel
    function setState(state) {
      this.state = state;
    }

    function hasFiles() {
      return this.uploader.queue.length > 0;
    }

    function getPopover(probe, results) {
      if(results.status === 0 || results.status === '0'){
        return {
          title: probe,
          content: 'File clean'
        };
      } else if(results.status === 1 || results.status === '1'){
        return {
          title: probe,
          content: 'File compromised'
        };
      } else if(results.status === 'loading'){
        return {
          title: probe,
          content: 'Waiting for response'
        };
      } else {
        return {
          title: probe,
          content: 'An error occured'
        };
      }
    }

    /*
     *  Upload handling:
     *  - Start:   Retrieves a scan id, sets the files url, start uploading
     *  - Cancel:  Stops the upload
     *  - Error:   Broadcasts the event
     *  - Done:    Checks for errors, broadcasts the appropriate event
     */
    function startUpload() {
      this.api.scan.createNew().then(function(response){
        this.id = response.id;

        var items = this.uploader.getNotUploadedItems();
        _.each(items, function(item){
          item.url = this.api.scan.getAddUrl(this);
        }.bind(this));

        $log.info('Upload has started');
        this.uploader.uploadAll();
      }.bind(this));
    }

    function cancelUpload() {
      $log.info('Upload was cancelled');
      this.uploader.cancelAll();
    }

    function errorUpload() {
      $rootScope.$broadcast('errorUpload');
    }

    function doneUpload(event, items) {
      if(!!_.find(items, function(item){ return (!item.isSuccess || item._xhr.status !== 200); })){
        this.errorUpload();
      } else {
        $rootScope.$broadcast('successUpload');
      }
    }

    function startScan() {
      var params = this.state.getLaunchParams();
      $log.info('Scan was launched');

      this.status = constants.scanStatusCodes.STARTED;
      this.api.scan.launch(this, params).then(function(response){
        this.updateScan();
      }.bind(this));
    }

    function cancelScan() {
      $log.info('Scan was cancelled');
      $timeout.cancel(this.task);
      if(this.id){
        this.api.scan.cancel(this);
      }
    }

    function updateScan() {
      this.api.scan.getInfos(this).then(function(data) {
        this.setProgress(data.probes_total, data.probes_finished);
        this.results = data.results;

        if(data.status === 1020){
          this.status = constants.scanStatusCodes.ERROR;
          alerts.add({standard: 'ftpError'});
        } else if (data.status !== 50) {
          this.status = constants.scanStatusCodes.RUNNING;
          this.task = $timeout(this.updateScan.bind(this), constants.refresh);
        } else {
          $log.info('Scan was successful');
          $rootScope.$broadcast('successScan');

          this.status = constants.scanStatusCodes.FINISHED;
        }
      }.bind(this), function(data) {
        this.task = $timeout(this.updateScan.bind(this), constants.refresh);
      }.bind(this));
    }

    function setProgress(total, finished) {
      this.scanProgress = {
        progress: Math.round(100 * finished / total),
        total: total,
        successful: finished,
        finished: finished
      };
    }

    function getResults() {
      $log.info('Updating results');

      return this.api.scan.getResults(this).then(function(data) {
        this.results = data;
      }.bind(this), function(data) {
        $rootScope.$broadcast('errorResults', data);
      }.bind(this));
    }

    function getResult(resultid) {
      $log.info('Retrieve file result ' + resultid);

      return api.scan.getResult(this, resultid);
    }

    
    function fileAdded(event, files){

      var hasher = operative({
        hash: function(file, callback) {
          var reader = new FileReaderSync();
          var buffer = reader.readAsBinaryString(file);
          var sha256 = CryptoJS.SHA256(buffer).toString()
          callback(sha256);
        }
      }, ['/scripts/worker.js']);

      var handler = function(file){
        return function(result){
          file.hash = result;

          if(_.filter(files, function(file){
            return _.isUndefined(file.hash)
          }).length === 0){
            console.log('fini');
          }
        }
      }

      _.map(files, function(file){
        hasher.hash(file.file, handler(file));
      });

      console.log(files);
    }
  }
}) ();
