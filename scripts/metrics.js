// author: InMon Corp.
// version: 1.0
// date: 1/27/2021
// description: Internet Exchange Provider (IXP) Metrics
// copyright: Copyright (c) 2021 InMon Corp. ALL RIGHTS RESERVED

include(scriptdir() + '/inc/trend.js');

var T = getSystemProperty('ixp.flow.t') || 15;
var N = getSystemProperty('ixp.flow.n') || 10;
var SEP = '_SEP_';

var syslogHost = getSystemProperty("ixp.syslog.host");
var syslogPort = getSystemProperty("ixp.syslog.port") || 514;
var facility = 16; // local0
var severity = 5;  // notice

var max_members = getSystemProperty('ixp.members.n') || 1000;

function sendWarning(msg) {
  if(syslogHost) syslog(syslogHost,syslogPort,facility,severity,msg);
  else logWarning(JSON.stringify(msg));
}

var trend = new Trend(300,1);
var points = {};

var members = storeGet('members') || {};

var macToMember = {};
var ipGroups = {};
function updateMemberInfo() {
  var memberToMac,memberToIP,member,name,macs,ips,conns,j,conn,vlan_list,k,vlan,mac;

  memberToMac = {};
  memberToIP = {};
  macToMember = {};

  if(!members.member_list || members.member_list.length === 0) return;

  for(i = 0; i < members.member_list.length; i++) {
    member = members.member_list[i];
    if(!member) continue;
    name = member.name;
    if(!name) continue;
    macs = [];
    ips = [];
    conns = member.connection_list;
    if(!conns) continue;
    for(j = 0; j < conns.length; j++) {
      conn = conns[j];
      vlan_list = conn.vlan_list;
      if(!vlan_list) continue;
      for(var k = 0; k < vlan_list.length; k++) {
        vlan = vlan_list[k];
        if(!vlan) continue;
        if(vlan.ipv4) {
          if(vlan.ipv4.address) ips.push(vlan.ipv4.address);
          if(vlan.ipv4.mac_addresses) macs = macs.concat(vlan.ipv4.mac_addresses);
        }
        if(vlan.ipv6) {
          if(vlan.ipv6.address) ips.push(vlan.ipv6.address);
          if(vlan.ipv6.mac_addresses) macs = macs.concat(vlan.ipv6.mac_addresses);
        }
        macs = macs.filter((mac,idx,arr) => arr.indexOf(mac) === idx && 'UNKNOWN' !== mac).map(mac => mac.replace(/:/g,'').toUpperCase());
        for(var m = 0; m < macs.length; m++) {
          let mac = macs[m];
          macToMember[mac] = name;
        }
      }
    }
    if(ips.length > 0) memberToIP[name] = ips;
    if(macs.length > 0) memberToMac[name] = macs;
  }
  setGroups('ixp_member',memberToIP);
  setMap('ixp_member',memberToMac);
}
updateMemberInfo();

// metrics
setFlow('ixp_bytes', {value:'bytes', t:T, fs: SEP, filter:'direction=ingress'});
setFlow('ixp_frames', {value:'frames', t:T, fs:SEP, filter:'direction=ingress'});
setFlow('ixp_src', {keys:'map:macsource:ixp_member', value:'bytes', n:N, t:T, fs:SEP, filter:'direction=ingress'});
setFlow('ixp_dst', {keys:'map:macdestination:ixp_member', value:'bytes', n:N, t:T, fs:SEP, filter:'direction=ingress'});
setFlow('ixp_pair', {keys:'map:macsource:ixp_member,map:macdestination:ixp_member', value:'bytes', n:20, t:T, fs:SEP, filter:'direction=ingress'});
setFlow('ixp_protocol', {keys:'ethernetprotocol', value:'bytes', n:N, t:T, fs:SEP, filter:'direction=ingress'}); 
setFlow('ixp_pktsize', {keys:'range:bytes:0:63,range:bytes:64:64,range:bytes:65:127,range:bytes:128:255,range:bytes:256:511,range:bytes:512:1023,range:bytes:1024:1517,range:bytes:1518:1518,range:bytes:1519', value:'frames', n:9, t:T, filter:'direction=ingress'});

// find member macs
setFlow('ixp_ip4', {keys:'macsource,group:ipsource:ixp_member',value:'bytes',log:true,flowStart:true, n:N, t:T, fs:SEP});
setFlow('ixp_ip6', {keys:'macsource,group:ip6source:ixp_member',value:'bytes',log:true,flowStart:true, n:N, t:T, fs:SEP});

// find BGP connections
setFlow('ixp_bgp', {keys:'or:[map:macsource:ixp_member]:[group:ipsource:ixp_member]:[group:ip6source:ixp_member],or:[map:macdestination:ixp_member]:[group:ipdestination:ixp_member]:[group:ip6destination:ixp_member]',value:'frames',filter:'tcpsourceport=179|tcpdestinationport=179',log:true,flowStart:true, n:N, t:T, fs:SEP});

// exceptions
setFlow('ixp_srcmacunknown', {keys:'macsource', value:'bytes', filter:'direction=ingress&map:macsource:ixp_member=null', n:N, t:T, fs:SEP});
setFlow('ixp_dstmacunknown', {keys:'macdestination', value:'bytes', filter:'direction=ingress&map:macdestination:ixp_member=null', n:N, t:T, fs:SEP});
setFlow('ixp_badprotocol', {keys:'macsource,ethernetprotocol', value:'frames', filter:'ethernetprotocol!=2048,2054,34525', n:N, t:T, fs:SEP, log:true, flowStart:true});

var other = '-other-';
function calculateTopN(metric,n,minVal,total_bps) {     
  var total, top, topN, i, bps;
  top = activeFlows('TOPOLOGY',metric,n,minVal,'edge');
  var topN = {};
  if(top) {
    total = 0;
    for(i in top) {
      bps = top[i].value * 8;
      topN[top[i].key] = bps;
      total += bps;
    }
    if(total_bps > total) topN[other] = total_bps - total;
  }
  return topN;
}

function calculateTopInterface(metric,n) {
  var top = table('TOPOLOGY','sort:'+metric+':-'+n);
  var topN = {};
  if(top) {
    for(var i = 0; i < top.length; i++) {
      var val = top[i][0];
      var port = topologyInterfaceToPort(val.agent,val.dataSource);
      if(port && port.node && port.port) {
        topN[port.node + SEP + port.port] = val.metricValue; 
      }
    }
  }
  return topN; 
}

function getMetric(res, idx, defVal) {
  var val = defVal;
  if(res && res.length && res.length > idx && res[idx].hasOwnProperty('metricValue')) val = res[idx].metricValue;
  return val;
}

function flowCount(flow) {
  var res = activeFlows('TOPOLOGY',flow,1,0,'edge');
  return res && res.length > 0 ? res[0].value : 0;
}

var bgp = {};
var bgpLastSweep = 0;
var bgpSweepInterval = 60 * 60 * 1000;
var bgpAgingMs = 7 * 24 * 60 * 60 * 1000;
function ageBGP(now) {
  if(now - bgpLastSweep < bgpSweepInterval) return;
  bgpLastSweep = now;

  for(var key in bgp) {
    if(now - bgp[key] > bgpAgingMs) {
      delete bgp[key];
    }
  }
}

setIntervalHandler(function(now) {
  points = {};

  points['bgp-connections'] = Object.keys(bgp).length;

  var bps = flowCount('ixp_bytes') * 8;
  points['top-5-memsrc'] = calculateTopN('ixp_src',5,1,bps);
  points['top-5-memdst'] = calculateTopN('ixp_dst',5,1,bps);
  points['top-5-mempair'] = calculateTopN('ixp_pair',5,1,bps);
  points['top-5-protocol'] = calculateTopN('ixp_protocol',5,1,bps);
  points['top-5-memunknownsrc'] = calculateTopN('ixp_srcmacunknown',5,1,0);
  points['top-5-memunknowndst'] = calculateTopN('ixp_dstmacunknown',5,1,0);

  // calculate packet size distribution
  var ix0=0,ix64=0,ix65=0,ix128=0,ix256=0,ix512=0,ix1024=0,ix1518=0,ix1519=0,sum=0;
  var res = activeFlows('TOPOLOGY','ixp_pktsize',9,0,'edge');
  if(res) {
    for(var i = 0; i < res.length; i++) {
      var value = res[i].value;
      sum += value;
      switch(res[i].key) {
      case 'true,false,false,false,false,false,false,false,false': ix0=value; break;
      case 'false,true,false,false,false,false,false,false,false': ix64=value; break;
      case 'false,false,true,false,false,false,false,false,false': ix65=value; break;
      case 'false,false,false,true,false,false,false,false,false': ix128=value; break;
      case 'false,false,false,false,true,false,false,false,false': ix256=value; break;
      case 'false,false,false,false,false,true,false,false,false': ix512=value; break;
      case 'false,false,false,false,false,false,true,false,false': ix1024=value; break;
      case 'false,false,false,false,false,false,false,true,false': ix1518=value; break;
      case 'false,false,false,false,false,false,false,false,true': ix1519=value; break;
      }
    }
  }  
  var scale = sum ? 100 / sum : 0;
  points['dist-0-63'] = ix0 * scale;
  points['dist-64'] = ix64 * scale;
  points['dist-65-127'] = ix65 * scale;
  points['dist-128-255'] = ix128 * scale;
  points['dist-256-511'] = ix256 * scale;
  points['dist-512-1023'] = ix512 * scale;
  points['dist-1024-1517'] = ix1024 * scale;
  points['dist-1518'] = ix1518 * scale;
  points['dist-1519-'] = ix1519 * scale;

  trend.addPoints(now,points);

  ageBGP(now);
},1);

setFlowHandler(function(flow) {
  switch(flow.name) {
  case 'ixp_ip4':
  case 'ixp_ip6':
    let [mmac,member] = flow.flowKeys.split(SEP);
    let macMem = macToMember[mmac];
    if(macMem) {
      if(member !== macMem) {
        sendWarning({ixp_evt:"assignment", mac:mmac, assigned:macMem, seen:member});
      }
    } else {
      sendWarning({ixp_evt:"missing", mac:mmac, member:member});
    } 
    break;
  case 'ixp_badprotocol':
    let [smac,ethtype] = flow.flowKeys.split(SEP);
    sendWarning({ixp_evt:"protocol", "mac":smac, "ethtype":ethtype});
    break;
  case 'ixp_bgp':
    let [mem1,mem2] = flow.flowKeys.split(SEP);
    let bgpkey = mem1 > mem2 ? mem2+SEP+mem1 : mem1+SEP+mem2;
    bgp[bgpkey] = flow.start;
    break;
  }
},['ixp_badprotocol','ixp_ip4','ixp_ip6','ixp_bgp']);

const prometheus_prefix = (getSystemProperty("prometheus.metric.prefix") || 'sflow_') + 'ixp_';

function prometheusName(str) {
  return str.replace(/[^a-zA-Z0-9_]/g,'_');
}

function prometheus() {
  var result = prometheus_prefix+'bgp_connections ' + (points['bgp-connections'] || 0) + '\n';

  // Protocols
  var prots = points['top-5-protocol'] || {};
  result += prometheus_prefix+'bps{ethtype="IPv4"} '+(prots['2048'] || 0)+'\n';
  result += prometheus_prefix+'bps{ethtype="IPv6"} '+(prots['34525'] || 0)+'\n';
  result += prometheus_prefix+'bps{ethtype="ARP"} '+(prots['2054'] || 0)+'\n';

  // Packet size distribution
  result += prometheus_prefix+'pktdist{size="0-63"} '+(points['dist-0-63'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="64"} '+(points['dist-64'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="65-127"} '+(points['dist-65-127'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="128-255"} '+(points['dist-128-255'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="256-511"} '+(points['dist-256-511'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="512-1023"} '+(points['dist-512-1023'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="1024-1517"} '+(points['dist-1024-1517'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="1518"} '+(points['dist-1518'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{size="1519-"} '+(points['dist-1519-'] || 0)+'\n';

  // Member traffic matrix
  var rows = activeFlows('TOPOLOGY','ixp_pair',max_members,0,'edge') || [];
  for(var i = 0; i < rows.length; i++) {
    let [src,dst] = rows[i].key.split(SEP);
    src = prometheusName(src);
    dst = prometheusName(dst);
    result += prometheus_prefix+'peering_bps{src="'+src+'",dst="'+dst+'"} '+(rows[i].value*8)+'\n';
  }

  return result;
}

setHttpHandler(function(req) {
  var result, i, rows, mems, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  if(path.length === 1 && 'txt' === req.format) {
    return prometheus();
  }
  if('json' !== req.format) throw "not_found";
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found"; 
      result = {};
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      break;
    case 'metric':
      if(path.length == 1) result = points;
      else {
        if(path.length != 2) throw "not_found";
        if(points.hasOwnProperty(path[1])) result = points[path[1]];
        else throw "not_found";
      }
      break;
    case 'matrix':
      if(path.length > 1) throw "not_found";
      result = [];
      rows = activeFlows('TOPOLOGY','ixp_pair',max_members,0,'edge') || [];
      for(i = 0; i < rows.length; i++) {
        var [src,dst] = rows[i].key.split(SEP);
        result.push({src:src,dst:dst,bps:rows[i].value*8});
      }
      break;
    case 'bgp':
      result = {};
      for(mems in bgp) {
        let [mem1,mem2] = mems.split(SEP);
        if(!result[mem1]) result[mem1] = [];
        if(!result[mem2]) result[mem2] = [];
        result[mem1].push(mem2);
        result[mem2].push(mem1);
      }
      break;
    case 'members':
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error || !req.body || !req.body.version || 1.0 > req.body.version) {
            throw "bad_request";
          }
          members = req.body;
          storeSet('members',members);
          updateMemberInfo();
          break;
        case 'GET':
          result = members;
          break;
        default:
          throw "bad_request";
      }
      break;
    default: throw 'not_found';
  } 
  return result;
});
