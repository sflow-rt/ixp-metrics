$(function() {
  var restPath = '../scripts/metrics.js/';
  var trendURL = restPath + 'trend/json';
  var membersURL = restPath + 'members/json';
  var locateURL = restPath + 'locations/json';
  var SEP = '_SEP_';

  function setNav(target) {
    $('.navbar .nav-item a[href="'+target+'"]').parent().addClass('active').siblings().removeClass('active');
    $(target).show().siblings().hide();
    window.sessionStorage.setItem('ixp_metrics_nav',target);
    window.history.replaceState(null,'',target);
  }

  var hash = window.location.hash;
  if(hash && $('.navbar .nav-item a[href="'+hash+'"]').length == 1) setNav(hash);
  else setNav(window.sessionStorage.getItem('ixp_metrics_nav') || $('.navbar .nav-item a').first().attr('href'));

  $('.navbar .nav-link').on('click', function(e) {
    var selected = $(this).attr('href');
    setNav(selected);
    if('#traffic' === selected) $.event.trigger({type:'updateChart'});
  });

  $('a[href^="#"]').on('click', function(e) {
    e.preventDefault();
  });

  $('#traffic').on('click', 'a', function(e) {
    e.preventDefault();
    var search = $(this).text();
    setNav('#query');
    $('#member_search').val(search);
    $('#submit').click();
  });

  var colors = $.inmon.stripchart.prototype.options.colors;

  var db = {};

  var ethtypes = {'2048':'IPv4', '2054':'ARP', '34525':'IPv6'};
  function printEthType(k,i) { return ethtypes[k] || '0x'+(parseInt(k).toString(16)) };

  $('#topsources').chart({
    type: 'topn',
    stack: true,
    includeOther: false,
    sep: SEP,
    metric: 'top-5-memsrc',
    legendHeadings: ['ASN','Name'],
    legendLinks: ['#',null],
    units: 'Bits per Second'},
  db);
  $('#topdestinations').chart({
    type: 'topn',
    stack: true,
    includeOther: false,
    sep: SEP,
    metric: 'top-5-memdst',
    legendHeadings: ['ASN','Name'],
    legendLinks: ['#',null],
    units: 'Bits per Second'},
  db);
  $('#toppairs').chart({
    type: 'topn',
    stack: true,
    includeOther: false,
    sep: SEP,
    metric: 'top-5-mempair',
    legendHeadings: ['ASN','Name','ASN','Name'],
    legendLinks: ['#',null,'#',null],
    units: 'Bits per Second'},
  db); 
  $('#topprotos').chart({
    type: 'topn',
    stack: true,
    sep: SEP,
    metric: 'top-5-protocol',
    legendHeadings: ['Eth. Type'],
    keyName: printEthType,
    units: 'Bits per Second'},
  db);
  $('#topunknownsrc').chart({
    type: 'topn',
    stack: true,
    includeOther:false,
    sep: SEP,
    metric: 'top-5-memunknownsrc',
    legendHeadings: ['Src Mac'],
    legendLinks: ['#'],
    units: 'Bits per Second'},
  db);
  $('#topunknowndst').chart({
    type: 'topn',
    stack: true,
    includeOther:false,
    sep: SEP,
    metric: 'top-5-memunknowndst',
    legendHeadings: ['Dst Mac'],
    legendLinks: ['#'], 
    units: 'Bits per Second'},
  db);
  $('#topnucast').chart({
    type: 'trend',
    stack: true,
    includeOther:false,
    sep: SEP,
    metrics: ['broadcast','multicast'],
    legend: ['Broadcast','Multicast'],
    units: 'Frames per Second'},
  db);
  $('#pktsizes').chart({
    type:'trend',
    metrics:['dist-0-63','dist-64','dist-65-127','dist-128-255','dist-256-511','dist-512-1023','dist-1024-1517','dist-1518','dist-1519-'],
    legend:['0-63','64','65-127','128-255','256-511','512-1023','1024-1517','1518','>1518'],
    stack:true,
    ymargin:0.05,
    units:'Percent'},
  db);
  $('#bgp').chart({
    type:'trend',
    metrics:['bgp-connections'],
    units: 'Member Connections'},
  db);

  $('#locateForm').submit(function( event ) {
    event.preventDefault();
    $('#location').hide();
    var search = $.trim($('#member_search').removeClass('is-invalid').val());
    var query;
    if(/^([0-9A-Fa-f]{2}[:-]?){5}[0-9A-Fa-f]{2}$/.test(search)) {
      query = { mac: search.replace(/[:-]/g,'').toUpperCase()};
    } else if(/^[0-9]{1,10}$/.test(search)) {
      query = { asn: search };
    } else {
      query = { name: search };
    }
    $.ajax({
      url: locateURL,
      type: 'GET',
      data: query,
      contentType: 'application/json',
      success: function(resp) {
        var rows;
        if(resp && resp.length > 0) {
          var rows = '';
          for(var i = 0; i < resp.length; i++) {
            rows += '<tr>';
            rows += '<td>' + (resp[i].node || '') + '</td>';
            rows += '<td>' + (resp[i].port || '') + '</td>';
            rows += '<td class="text-right">' + (resp[i].speed ? $.inmon.stripchart.prototype.valueStr(resp[i].speed) : '') + '</td>';
            rows += '<td>' + (resp[i].mac || '') + '</td>';
            rows += '<td class="text-right">' + (resp[i].vlan || '') + '</td>';
            rows += '<td class="text-right">' + (resp[i].asn || '') + '</td>';
            rows += '<td>' + (resp[i].name || '') + '</td>';
            rows += '</tr>';
          }
          $('#location tbody').html(rows);
          $('#location').show();
        } else {
          $('#member_search').addClass('is-invalid');
        }
      },
      error: function() {
        $('#member_search').addClass('is-invalid');
      } 
    });
  });

  $('#membersFile').change(function(event) {
    var input = event.target;
    var $input = $(input);
    $input.removeClass('is-valid').removeClass('is-invalid');
    var file = input.files[0];
    var label = input.nextElementSibling;
    label.innerText = file.name;
    var reader = new FileReader();
    reader.onload = function() {
      var text = reader.result;
      $.ajax({
        url: membersURL,
        type: 'POST',
        contentType: 'application/json',
        data: text,
        success: function() { $input.addClass('is-valid'); },
        error: function() { $input.addClass('is-invalid'); } 
      });
    }
    reader.readAsText(file);
  });  

  function updateData(data) {
    if(!data 
      || !data.trend 
      || !data.trend.times 
      || data.trend.times.length == 0) return;
    
    if(db.trend) {
      // merge in new data
      var maxPoints = db.trend.maxPoints;
      db.trend.times = db.trend.times.concat(data.trend.times);
      var remove = db.trend.times.length > maxPoints ? db.trend.times.length - maxPoints : 0;
      if(remove) db.trend.times = db.trend.times.slice(remove);
      for(var name in db.trend.trends) {
        db.trend.trends[name] = db.trend.trends[name].concat(data.trend.trends[name]);
        if(remove) db.trend.trends[name] = db.trend.trends[name].slice(remove);
      }
    } else db.trend = data.trend;
    
    db.trend.start = new Date(db.trend.times[0]);
    db.trend.end = new Date(db.trend.times[db.trend.times.length - 1]);
    db.trend.values = data.trend.values;

    $.event.trigger({type:'updateChart'});
  }

  (function pollTrends() {
    $.ajax({
      url: trendURL,
      dataType: 'json',
      data: db.trend && db.trend.end ? {after:db.trend.end.getTime()} : null,
      success: function(data) {
        if(data) {
          updateData(data);
        } 
      },
      complete: function(result,status,errorThrown) {
        setTimeout(pollTrends,1000);
      },
      timeout: 60000
    });
  })();

  $(window).resize(function() {
    $.event.trigger({type:'updateChart'});
  });
});
