#! /usr/bin/env python
"""
Usage: nmap-scan -f FILE [(--host HOST --port PORT --database DB --collection COLLECTION)] [--hosts] [--raw] [--insert] [--snmp] [--ansible] [--debug]
options:
    --host HOST                            Mongo Host(default: localhost)
    --port PORT                            Mongo Port(default: 3001)
    --database DB                          Add records to mongo db
    --collection COLLECTION                Add records to mongo collection
    -H, --hosts                            Print *nix hosts file format
    -R, --raw                              Print raw collection database
    -I, --insert                           Performs insert instead of in place update
    -S, --snmp                             Make SNMP calls
    -A, --ansible                          Make Ansible inventory
    -D, --debug                            Print debug information

"""
from pysnmp.entity.rfc3413.oneliner import cmdgen
import xml.etree.ElementTree as ET
from docopt import docopt
from pprint import pprint
from pymongo import MongoClient
import datetime


def debug(msg, obj):
  print "DEBUG: {0} {1}\n".format(msg, pprint(obj))


def parsexml(file):
  _host = {}
  tree = ET.parse(file)
  hosts = tree.findall('host')
  for host in hosts:
    if ET.iselement(host):
      hostname = host.find("./hostnames/hostname").get('name') if ET.iselement(host.find("./hostnames/hostname")) else None
      #if ET.iselement(addresses):
      for addr in host.findall("address"):
          _address_type = addr.get('addrtype')
          if _address_type == 'ipv4':
            _ipaddress = addr.get('addr')
            _ipaskey = _ipaddress.replace(".", "-")
            _macaddress = None
            _vendor = None
            # _host[_ipaskey] = []
          if _address_type == 'mac':
            _macaddress = addr.get('addr')
            _vendor = addr.get('vendor')
          if (args['--snmp']):
            (errI, errS, varBind) = snmpget(_ipaddress)
      # Per Host
      _host[_ipaskey] = { '_id': _ipaskey, 'name': hostname, 'ip': _ipaddress, 'mac': _macaddress, 'vendor': _vendor}
      _services = {}
      for port in host.findall("./ports/port"):
          if ET.iselement(port):
            if port.find(".//state/[@state='open']") is not None:
              #Per open Port
              state = port.find(".//state/[@state='open']")
              service = port.find('service')

              if port.get("portid") == "443":
                common_name = port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='commonName']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='commonName']")) else None
                valid_after = port.find("./script/[@id='ssl-cert']/table/[@key='validity']/elem/[@key='notAfter']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='validity']/elem/[@key='notAfter']")) else None
                orgname     = port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='organizationName']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='organizationName']")) else None
                _service = {'protocol'            :  port.get("protocol"),
                               'portid'           :  port.get("portid"),
                               'product'          :  service.get("product"),
                               'service_name'     :  service.get("name"),
                               'ssl_cn'           :  common_name,
                               'ssl_orgname'      :  orgname,
                               'ssl_valid'        :  valid_after,}
              else: 
                _service =    {'protocol'        :  port.get("protocol"),
                               'portid'           :  port.get("portid"),
                               'product'          :  service.get("product"),
                               'service_name'     :  service.get("name"),}

              if port.get("portid") not in _services.values():
                  _services.setdefault('services',[]).append(_service)


    _host[_ipaskey].update(_services)
    del _services

  if args["--debug"]:
    debug("_host Object", _host)

  return _host


def snmpget(host):

  cmdGen = cmdgen.CommandGenerator()

  errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
      cmdgen.CommunityData('public'),
      cmdgen.UdpTransportTarget((host, 161)),
      cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
      lookupNames=True, lookupValues=True
  )

  # Check for errors and print out results
  if errorIndication:
      errI = errorIndication
  elif errorStatus:
      errS = errorStatus
  else:
      for name, val in varBinds:
          print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
      return varBinds


def print_hosts(collection):
   for k,v in collection.iteritems():
      if v['name'] is not None:
	     print "%s\t%s" % (k,v['name'])


def print_ansible(collection):
  for i in collection:
    print "%s\tansible_ssh_user=%s\tansible_ssh_pass=%s" % (i, 'root', '#cdtg-root#')       


def print_raw(collection):
    pprint(collection)

def update_collection(collection,  col):
  timestamp = str(datetime.datetime.now())

  for i in collection:
    collection[i].update({'updated': timestamp})
    query = { "_id" : i }
  # query_one = { ip : i }, {{ ip : 1 }
    if args['--insert']:
      insert(collection[i], col)
    else:
      find_and_modify(query, collection[i],  col)


def get_mongo_handle(client, database, collection):
    """
    Get a collections handle in a database returns database and collection object
    """

    db = getattr(client,database) 
    # db = client.fastops
    col = getattr(db,collection)
    #db = client.fastops
    #col = db.hosts
    return (db, col)


def find_and_modify(query, record, col):
    """
    Find a document in collection based on index and update
    """
    retval = col.find_and_modify(query, update={'$set' : record}, upsert=True,  new=True)

    return retval

def find(query, col):
    """
    Find a document in collection based on query
    """
    retval = col.find(query).count()

    if retval > 1:
      return True
    else:
      return False

def find_one(query, col):
    """
    Find a document in collection based on query
    """
    retval = col.find_one(query)
    if retval is not None:  
      return True
    else:
      return False

def insert(record, col):
    """
    Find a document in collection based on query
    """
    retval = col.insert(record, manipulate=True)

    if retval is not None:
      return True
    else:
      return False


if __name__ == "__main__":
   args = docopt(__doc__)
   records = parsexml(args['FILE'])
   if args["--hosts"]:
    print_hosts(records)   
   if args["--ansible"]:
    print_ansible(records)
   if args["--raw"]:
    print_raw(records)

   
   if args["--host"]:
    url = "mongodb://{host}:{port}/".format(host=args["--host"], port=args["--port"])
    client = MongoClient(url)
    (db, col)  = get_mongo_handle(client, args["--database"], args["--collection"])
    update_collection(records, col)
    client.close()


