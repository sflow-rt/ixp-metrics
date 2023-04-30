// author: InMon Corp.
// version: 1.2
// date: 4/27/2023
// description: Internet Exchange Provider (IXP) Metrics
// copyright: Copyright (c) 2021-2023 InMon Corp. ALL RIGHTS RESERVED

include(scriptdir() + '/inc/trend.js');

var N = getSystemProperty('ixp.flow.n') || 20;
var T = getSystemProperty('ixp.flow.t') || 15;
var MAX_MEMBERS = getSystemProperty('ixp.members.n') || 1000;
var ETHTYPE = getSystemProperty('ixp.allowed.ethertype') || '2048,2054,34525';
var SYSLOG_HOST = getSystemProperty("ixp.syslog.host");
var SYSLOG_PORT = getSystemProperty("ixp.syslog.port") || 514;
var FACILITY = getSystemProperty("ixp.syslog.facility") || 16; // local0
var SEVERITY = getSystemProperty("ixp.syslog.severity") || 5;  // notice

var TOP_N = 5;
var MIN_VAL = 1;
var SEP = '_SEP_';

function sendWarning(msg) {
  if(SYSLOG_HOST) syslog(SYSLOG_HOST,SYSLOG_PORT,FACILITY,SEVERITY,msg);
  else logWarning(JSON.stringify(msg));
}

var trend = new Trend(300,1);
var points = {};

var members = storeGet('members') || {};

var macToMember = {};
var learnedMacToMember = {};
function updateMemberInfo() {
  var memberToMac,memberToIP,member,name,asn,rec,macs,ips,conns,j,conn,vlan_list,k,vlan,mac;

  memberToMac = {};
  memberToIP = {};
  macToMember = {};
  learnedMacToMember = {};

  if(!members.member_list || members.member_list.length === 0) return;

  for(i = 0; i < members.member_list.length; i++) {
    member = members.member_list[i];
    if(!member) continue;
    asn = member.asnum;
    if(!asn) continue;
    name = member.name;
    if(!name) continue;
    rec = asn.toString() + SEP + name;
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
          macToMember[mac] = rec;
        }
      }
    }
    if(ips.length > 0) memberToIP[rec] = ips;
    if(macs.length > 0) memberToMac[rec] = macs;
  }
  setGroups('ixp_member',memberToIP);
  setMap('ixp_member',memberToMac);
}
updateMemberInfo();

// metrics
//EDGE_FILTER used when logging flows to select edge measurements
// Note: activeFlows() de-duplicates so not needed for metrics
var EDGE_FILTER = 'direction=ingress&link:inputifindex=null';
setFlow('ixp_bytes', {
  value:'bytes',
  t:T,
  fs: SEP
});
setFlow('ixp_frames', {
  value:'frames',
  t:T,
  fs:SEP
});
setFlow('ixp_src', {
  keys:'map:macsource:ixp_member',
  value:'bytes',
  n:TOP_N,
  t:T,
  fs:SEP
});
setFlow('ixp_dst', {
  keys:'map:macdestination:ixp_member',
  value:'bytes',
  n:TOP_N,
  t:T,
  fs:SEP
});
setFlow('ixp_pair', {
  keys:'map:macsource:ixp_member,map:macdestination:ixp_member',
  value:'bytes',
  n:N,
  t:T,
  fs:SEP
});
setFlow('ixp_protocol', {
  keys:'ethernetprotocol',
  value:'bytes',
  n:TOP_N,
  t:T,
  fs:SEP
}); 
setFlow('ixp_pktsize', {
  keys:'range:bytes:0:63,range:bytes:64:64,range:bytes:65:127,range:bytes:128:255,range:bytes:256:511,range:bytes:512:1023,range:bytes:1024:1517,range:bytes:1518:1518,range:bytes:1519',
  value:'frames',
  n:9,
  t:T,
  fs:','
});

// find member macs
setFlow('ixp_ip4', {
  keys:'macsource,group:ipsource:ixp_member',
  filter:EDGE_FILTER+'&first:stack:.:ip:ip6=ip',
  value:'bytes',
  t:T,
  fs:SEP,
  log:true,
  flowStart:true
});
setFlow('ixp_ip6', {
  keys:'macsource,group:ip6source:ixp_member',
  filter:EDGE_FILTER+'&first:stack:.:ip:ip6=ip6',
  value:'bytes',
  t:T,
  fs:SEP,
  log:true,
  flowStart:true
});

// find BGP connections
// BGP_FILTER used to detect established BGP connections
var BGP_FILTER = 'tcpflags~....1.000&(tcpsourceport=179|tcpdestinationport=179)';
setFlow('ixp_bgp', {
  keys:'or:[map:macsource:ixp_member]:[group:ipsource:ixp_member],or:[map:macdestination:ixp_member]:[group:ipdestination:ixp_member],macsource,macdestination,ipsource,ipdestination',
  filter:EDGE_FILTER+'&first:stack:.:ip:ip6=ip&'+BGP_FILTER,
  value:'frames',
  t:T,
  fs:SEP,
  log:true,
  flowStart:true
});
setFlow('ixp_bgp6', {
  keys:'or:[map:macsource:ixp_member]:[group:ip6source:ixp_member],or:[map:macdestination:ixp_member]:[group:ip6destination:ixp_member],macsource,macdestination,ip6source,ip6destination',
  filter:EDGE_FILTER+'&first:stack:.:ip:ip6=ip6&'+BGP_FILTER,
  value:'frames',
  t:T,
  fs:SEP,
  log:true,
  flowStart:true
});

// exceptions
setFlow('ixp_srcmacunknown', {
  keys:'macsource',
  filter:'map:macsource:ixp_member=null',
  value:'bytes',
  n:TOP_N,
  t:T,
  fs:SEP
});
setFlow('ixp_dstmacunknown', {
  keys:'macdestination',
  filter:'map:macdestination:ixp_member=null',
  value:'bytes',
  n:TOP_N,
  t:T,
  fs:SEP
});
setFlow('ixp_badprotocol', {
  keys:'macsource,ethernetprotocol',
  filter:EDGE_FILTER+'&ethernetprotocol!='+ETHTYPE,
  value:'frames',
  t:T,
  fs:SEP,
  log:true,
  flowStart:true
});

// BUM
setFlow('ixp_nunicast', {
  keys:'macsource,macdestination,ethernetprotocol',
  filter:'isbroadcast=true|ismulticast=true',
  value:'frames',
  n:TOP_N,
  t:T,
  fs:SEP
});
// t=600 since these should be rare
setFlow('ixp_arp', {
  keys:'macsource,macdestination,arpoperation,arpipsender,arpiptarget',
  value:'frames',
  n:20,
  t:600,
  fs:SEP
});
setFlow('ixp_nunicast', {
  keys:'macsource,macdestination,ethernetprotocol',
  filter:'isbroadcast=true|ismulticast=true',
  value:'frames',
  n:20,
  t:600,
  fs:SEP
});

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
  var res = activeFlows('TOPOLOGY',flow,MIN_VAL,0,'edge');
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
    if(now - bgp[key].lastUpdate > bgpAgingMs) {
      delete bgp[key];
    }
  }
}

setIntervalHandler(function(now) {
  points = {};

  // query counters for total bps in/out
  var counters = metric('EDGE','sum:ifinoctets,sum:ifoutoctets,sum:ifinbroadcastpkts,sum:ifinmulticastpkts',{iftype:['ethernetCsmacd']});
  points['bps_in'] = getMetric(counters,0,0) * 8; 
  points['bps_out'] = getMetric(counters,1,0) * 8;
  points['broadcast'] = getMetric(counters,2,0);
  points['multicast'] = getMetric(counters,3,0);

  points['bgp-connections'] = Object.keys(bgp).length;

  var bps = flowCount('ixp_bytes') * 8;
  var fps = flowCount('ixp_frames');
  points['bps'] = bps;
  points['fps'] = fps;
  points['top-5-memsrc'] = calculateTopN('ixp_src',TOP_N,MIN_VAL,bps);
  points['top-5-memdst'] = calculateTopN('ixp_dst',TOP_N,MIN_VAL,bps);
  points['top-5-mempair'] = calculateTopN('ixp_pair',TOP_N,MIN_VAL,bps);
  points['top-5-protocol'] = calculateTopN('ixp_protocol',TOP_N,MIN_VAL,bps);
  points['top-5-memunknownsrc'] = calculateTopN('ixp_srcmacunknown',TOP_N,MIN_VAL,0);
  points['top-5-memunknowndst'] = calculateTopN('ixp_dstmacunknown',TOP_N,MIN_VAL,0);

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
    let [mmac,asn,name] = flow.flowKeys.split(SEP);
    learnedMacToMember[mmac] = asn+SEP+name;
    let macMem = macToMember[mmac];
    if(macMem) {
      let [mac_asn,mac_name] = macMem.split(SEP);
      if(asn !== mac_asn) {
        sendWarning({ixp_evt:"assignment", mac:mmac, assigned:mac_asn, seen:asn});
      }
    } else {
      sendWarning({ixp_evt:"missing", mac:mmac, member:asn});
    } 
    break;
  case 'ixp_badprotocol':
    let [smac,ethtype] = flow.flowKeys.split(SEP);
    sendWarning({ixp_evt:"protocol", "mac":smac, "ethtype":ethtype});
    break;
  case 'ixp_bgp':
  case 'ixp_bgp6':
    let [asn1,name1,asn2,name2,mac1,mac2,addr1,addr2] = flow.flowKeys.split(SEP);
    if(mac1 > mac2) {
      bgp[addr1+','+addr2] = {
        member1: {asn:asn1,name:name1,mac:mac1,addr:addr1},
        member2: {asn:asn2,name:name2,mac:mac2,addr:addr2},
        lastUpdate:flow.start
      };
    } else {
      bgp[addr2+','+addr1] = {
        member1: {asn:asn2,name:name2,mac:mac2,addr:addr2},
        member2: {asn:asn1,name:name1,mac:mac1,addr:addr1},
        lastUpdate:flow.start
      };
    }
    break;
  }
},['ixp_badprotocol','ixp_ip4','ixp_ip6','ixp_bgp','ixp_bgp6']);

const prometheus_prefix = (getSystemProperty("prometheus.metric.prefix") || 'sflow_') + 'ixp_';

function prometheusName(str) {
  return str.replace(/[^a-zA-Z0-9_]/g,'_');
}

function prometheus() {
  var result = prometheus_prefix+'bgp_connections ' + (points['bgp-connections'] || 0) + '\n';

  // Total traffic in/out based on counters
  result += prometheus_prefix+'bps_total{direction="in"} '+(points['bps_in'] || 0)+'\n';
  result += prometheus_prefix+'bps_total{direction="out"} '+(points['bps_out'] || 0)+'\n';

  // Total traffic in/out based on packet samples
  result += prometheus_prefix+'bps '+(points['bps'] || 0)+'\n';
  result += prometheus_prefix+'fps '+(points['fps'] || 0)+'\n';

  // Protocols
  var prots = points['top-5-protocol'] || {};
  result += prometheus_prefix+'bps{ethtype="IPv4"} '+(prots['2048'] || 0)+'\n';
  result += prometheus_prefix+'bps{ethtype="IPv6"} '+(prots['34525'] || 0)+'\n';
  result += prometheus_prefix+'bps{ethtype="ARP"} '+(prots['2054'] || 0)+'\n';

  // Packet size distribution
  result += prometheus_prefix+'pktdist{bin="0",size="0-63"} '+(points['dist-0-63'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="1",size="64"} '+(points['dist-64'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="2",size="65-127"} '+(points['dist-65-127'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="3",size="128-255"} '+(points['dist-128-255'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="4",size="256-511"} '+(points['dist-256-511'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="5",size="512-1023"} '+(points['dist-512-1023'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="6",size="1024-1517"} '+(points['dist-1024-1517'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="7",size="1518"} '+(points['dist-1518'] || 0)+'\n';
  result += prometheus_prefix+'pktdist{bin="8",size="1519-"} '+(points['dist-1519-'] || 0)+'\n';

  // Member traffic matrix
  var rows = activeFlows('TOPOLOGY','ixp_pair',MAX_MEMBERS,MIN_VAL,'edge') || [];
  for(var i = 0; i < rows.length; i++) {
    let [src_asn,src_name,dst_asn,dst_name] = rows[i].key.split(SEP);
    src_name = prometheusName(src_name);
    dst_name = prometheusName(dst_name);
    result += prometheus_prefix+'peering_bps{src_asn="'+src_asn+'",src_name="'+src_name+'",dst_asn="'+dst_asn+'",dst_name="'+dst_name+'"} '+(rows[i].value*8)+'\n';
  }

  return result;
}

function memberCounters(name,n) {
  var result = [];
  var rows = table('EDGE','sort:'+name+':-'+n);
  for(i = 0; i < rows.length; i++) {
    var row = rows[i][0];
    if(!row.metricValue) break;
    var entry = {agent:row.agent,ifindex:row.dataSource,value:row.metricValue};
    var port = topologyInterfaceToPort(row.agent,row.dataSource);
    if(port) {
      entry.node = port.node;
      entry.port = port.port; 
    }
    result.push(entry);
  }
  return result;
}

function memberLocations(find_mac,find_asn,find_name) {
  var locations = [];
  var macs = find_mac || topologyLocatedHostMacs();
  if(!macs) return locations;
  for each (var mac in macs) {
    var locs = topologyLocateHostMac(mac);
    if(!locs) continue;
    for each (var loc in locs) {
      var entry = {};
      entry.mac = mac;
      entry['ouiname'] = loc.ouiname || '';
      entry['node'] = loc.node || loc.agent;
      entry['port'] = loc.port || loc.ifindex;
      entry['vlan'] = loc.vlan || '';

      var member = macToMember[mac] || learnedMacToMember[mac];
      if(member) {
        var [asn,name] = member.split(SEP);
        entry['asn'] = asn;
        entry['name'] = name;
      }
      if(find_asn && !find_asn.includes(entry.asn || '')) continue;
      if(find_name && !find_name.some((val) => (entry.name || '').toLowerCase().indexOf(val.toLowerCase()) >= 0)) continue;
      locations.push(entry);
    }
  }
  return locations;
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
      rows = activeFlows('TOPOLOGY','ixp_pair',MAX_MEMBERS,MIN_VAL,'edge') || [];
      for(i = 0; i < rows.length; i++) {
        let [src_asn,src_name,dst_asn,dst_name] = rows[i].key.split(SEP);
        result.push({src_asn:src_asn,src_name:src_name,dst_asn:dst_asn,dst_name:dst_name,bps:rows[i].value*8});
      }
      break;
    case 'bgp':
      result = [];
      for(key in bgp) {
        result.push(bgp[key]);
      }
      break;
    case 'arp':
       result = [];
       rows = activeFlows('TOPOLOGY','ixp_arp',100,MIN_VAL,'edge') || [];
       for(i = 0; i < rows.length; i++) {
         let [macsource,macdestination,arpoperation,arpipsender,arpiptarget] = rows[i].key.split(SEP);
         result.push({smac:macsource,dmac:macdestination,op:arpoperation,sender:arpipsender,target:arpiptarget,fps:rows[i].value});
       }
       break;
    case 'nunicast':
       result = [];
       rows = activeFlows('TOPOLOGY','ixp_nunicast',100,MIN_VAL,'edge') || [];
       for(i = 0; i < rows.length; i++) {
         let [macsource,macdestination,ethernetprotocol] = rows[i].key.split(SEP);
         result.push({smac:macsource,dmac:macdestination,ethtype:ethernetprotocol,fps:rows[i].value});
       }
       break;
    case 'multicast':
       result = memberCounters('ifinmulticastpkts',10);;
       break; 
    case 'broadcast':
       result = memberCounters('ifinbroadcastpkts',10);
       break;
    case 'locations':
       result = memberLocations(req.query['mac'],req.query['asn'],req.query['name']);
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
