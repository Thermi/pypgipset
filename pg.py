#! /bin/env python3

#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import gzip
import http.client
import ipaddress
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
import zlib


COUNTRIES=[
    "af",
    "ae",
    "ir",
    "iq",
    "tr",
    "cn",
    "sa",
    "sy",
    "ru",
    "ua",
    "hk",
    "id",
    "kz",
    "kw",
    "ly"
    ]

# BLUETACKALIAS=[
#     "DShield",
#     "Bogon",
#     "Hijacked",
#     "DROP",
#     "ForumSpam",
#     "WebExploit",
#     "Ads",
#     "Proxies",
#     "BadSpiders",
#     "CruzIT",
#     "Zeus",
#     "Palevo",
#     "Malicious",
#     "Malcode",
#     "Adservers"
#     ]

BLUETACK=[
    "xpbqleszmajjesnzddhv",
    "lujdnbasfaaixitgmxpp",
    "usrcshglbiilevmyfhse",
    "zbdlwrqkabxbcppvrnos",
    "ficutxiwawokxlcyoeye",
    "ghlzqtqxnzctvvajwwag",
    "dgxtneitpuvgqqcpfulq",
    "xoebmbyexwuiogmbyprb",
    "mcvxsnihddgutbjfbghy",
    "czvaehmjpsnwwttrdoyl",
    "ynkdjqsjyfmilsgbogqf",
    "erqajhwrxiuvjxqrrwfj",
    "npkuuhuxcsllnhoamkvm",
    "pbqcylkejciyhmwttify",
    "zhogegszwduurnvsyhdf"
    ]

ENABLE_BLUETACK=True
ENABLE_COUNTRY=False
ENABLE_TORBLOCK=True

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class network:
    network = None
    mask = None
    def __init__(self, subnet):
        network = ipaddress.ip_network(subnet)
        self.network = int(network.network_address)
        self.mask = int(network.netmask)

invalidV4 = list() 
for i in [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12",
    "192.168.0.0/16", "169.254.0.0/16", "255.0.0.0/8",
    "224.0.0.0/4"
    ]:
    invalidV4.append(network(i))

invalidV6 = list()
for i in [
    "ff00::/8", "fe80::/10", "fd00::/8"
    ]:
    invalidV6.append(network(i))


# From https://stackoverflow.com/questions/13044562/python-mechanism-to-identify-compressed-file-type-and-uncompress
magic_dict = {
    b"\x1f\x8b\x08": "gz",
    b"\x42\x5a\x68": "bz2",
    b"\x50\x4b\x03\x04": "zip"
    }

def detectType(stream):
    # max_len = max(len(x) for x in magic_dict)
    # get max_len bytes
    theseBytes=stream[:max(len(x) for x in magic_dict)]
    for magic, filetype in magic_dict.items():
        if theseBytes.startswith(magic):
            return filetype
    return "No match"

class request():
    server = ""
    urls = []

    def __init__(self, server, urls):
        self.server = server
        self.urls = urls

class pgPy:
    unifiedList=[]
    duplicateList=[]

    temporaryNameTemplate = "peer-guardian-temporary"
    permanentNameTemplate = "peer-guardian-permanent"
    # tries to get a block list from the given urls (a list of "url" objects).
    # The urls must all be retrievable from the same server.
    # returns a list of lists that contain the decompressed responses that the server sent, if the list could be gotten successfully.
    # They are not ordered in any way.
    def getList(self, serverURI, urls=[]):
        redirects=[]
        theseLists=[]
        connection=None
        result = urlparse(serverURI)
        if result.netloc != "":
            netloc = result.netloc
        else:
            netloc = serverURI

        if result.scheme == "http" or result.scheme == "":
            connection = http.client.HTTPConnection(netloc, timeout=5)
        elif result.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_COMPRESSION
            # initiate a secure HTTPS connection to get the list
            connection = http.client.HTTPSConnection(netloc, 
                context = ctx , timeout=5)
        else:
            eprint("Unknown scheme: ", result.scheme)
            return []

        if result.path != "":
            urls.append(result.path)

        try:
            connection.connect()
        except:
            eprint ("Error while connecting: ", sys.exc_info())
            return theseLists

        for i in urls:
            try:
                connection.request("GET", i)
                response = connection.getresponse()
            except socket.error as e:
                eprint ("Socket error: {}".format(e))
                continue
            except socket.timeout as timeout:
                eprint ("Socket error: Connection timed out.")
                continue


            if response.status == 302:
                # read the location header and parse the URL
                headers=response.getheaders()
                for j,k in headers:
                    if j == "Location":
                        redirects.append(k)
                        break
                        break
            elif response.status != 200:
                eprint ("Server responded with statuscode {}. Aborting".format(response.status))
                response.read()
                response.close()
                continue
            
            body = response.read()
            if len(body) == 0:
                continue
            if response.info().get('Content-Encoding') == 'gz':
                # ungzip
                decompressTransport=zlib.decompress(body, 16+zlib.MAX_WBITS)
                # Now to check the actual bytes:
                if detectType(decompressTransport) == "gz":
                    # decompress once more.
                    theseLists.append(zlib.decompress(decompressTransport, 16+zlib.MAX_WBITS))
                else:
                    theseLists.append(decompressTransport)
            else:
                if detectType(body) == "gz":
                    # decompress gzip file format
                    theseLists.append(zlib.decompress(body, 16+zlib.MAX_WBITS))
                else:
                    theseLists.append(body)

        if len(redirects) > 0:
            # parse the urls, unify by network location (server)
            serversWithUrls={}
            num=0
            for i in redirects:
                result2=urlparse(i)
                value=serversWithUrls.get(result2.netloc)
                # print("i: {} Result: {}".format(num, result2))
                if value != None:
                    value.append(result2.path)
                    # print("Set {} to {}".format(result2.netloc, result2.path))
                else:
                    location=""
                    if result2.netloc =="":
                        location=result.netloc
                    else:
                        location=result2.netloc
                    serversWithUrls[location] = [result2.path]
                    # print("Set {} to {}".format(location, result2.path))

                num+=1
            for j in serversWithUrls.keys():
                theseLists.extend(self.getList(j, serversWithUrls[j]))
            

        return theseLists

    def restoreFile(self, filename):
        cmd = "ipset -exist -f {} restore".format(filename).split(" ")
        
        process = subprocess.Popen(cmd)
        process.wait()
        
        if process.returncode != 0:
            print("Restoring the file {} failed with code {}".format(filename, process.returncode))
            return False
        
    def deriveNames(self, name):
        v4 = "-v4"
        v6 = "-v6"
        return "{}{}".format(name, v4), "{}{}".format(name, v6)
    
    def destroySet(self, set_1):
        cmd = "ipset destroy {}".format(set_1).split(" ")
        
        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            print("Deleting the ipset {} failed with code {}".format(set_1, process.returncode))
            return False
        return True
    
    def swapSets (self, set_1, set_2):
        cmd = "ipset swap {} {}".format(set_1, set_2).split(" ")

        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            eprint("Swapping the ipsets {} and {} failed with code {}".format(set_1, set_2, process.returncode))
            return False
        return True
    
    def writeHeader(self, temporary_file_handle, header):
        temporary_file_handle.write(bytearray("{}\n".format(header), 'utf-8'))
        temporary_file_handle.flush()
    

    def generateFileHeader(self, name, settype="hash:ip", comment=True, family="inet", hashsize=1024, maxelem=1000000):
        format_string=None
        if comment:
            format_string = "create {} {} family {} hashsize {} maxelem {} comment"
        else:
            format_string = "create {} {} family {} hashsize {} maxelem {}"
        return format_string.format(name, settype, family, hashsize, maxelem)

    # https://docs.python.org/3/library/ipaddress.html#ipaddress.summarize_address_range
    def convertRangeIntoCidr(self, first, last):
        if first == last:
            return ipaddress.ip_address(first)
        outputIPNetworks=[ipaddr for ipaddr in ipaddress.summarize_address_range(
            first, last)]
        return outputIPNetworks

    # This merges the lists in the list "lists" and returns a list that contains the
    # members of all lists, minus any duplicates.
    def mergeLists(self, thisList):
        # empty dictionary (hashtable, very fast)
        d = {}
        for i in thisList:
            if i in d:
                pass
            else:
                d[i] = 1
        return d.keys()

    # gets the bluetack block lists.
    # Every item in BLUETACK
    # This list only contains IPv4 addresses in host notation, without prefix length.
    def bluetack(self):
        # make a list of all the possible URLs
        theseUrls=[]
        # iterate over the possible combinations
        for i in BLUETACK:
            theseUrls.append("/?list={}&fileformat=p2p".format(i))
        
        response = self.getList("http://list.iblocklist.com", theseUrls)
        for i in response:
            if i == None:
                break
            # interpret as ascii, split by newlines
            try:
                theseLines=i.decode().split("\n")
                for j in theseLines:
                    if j.startswith("#") or j == "":
                        continue
                    splits=j.rsplit(sep=":")
                    iprange=splits[1]
                    ips = iprange.strip().split(sep="-")
                    ret = self.convertRangeIntoCidr(ipaddress.ip_address(ips[0]), ipaddress.ip_address(ips[1]))
                    if hasattr(ret, "__iter__"):
                        for k in ret:
                            self.duplicateList.append(k)
                    else:
                        self.duplicateList.append(ret)
            except:
                print ("Exception: ",sys.exc_info())
#                print ("Data: ", i)
    # gets the country block list
    # this list only contains CIDR subnets
    def country(self):
        theseUrls=[]

        for i in COUNTRIES:
            theseUrls.append("/ipblocks/data/countries/{}.zone".format(i))
        response = self.getList("http://www.ipdeny.com", theseUrls)
        for i in response:
            # interpret as ascii, split by newlines
            # this file only contains CIDR subnets
            theseLines=i.decode().split("\n")
            for j in theseLines:
                self.duplicateList.append(ipaddress.IPv4Network(j))

    # gets the tor block list
    # This is the complete TOR exit node list from https://check.torproject.org/exit-addresses
    def torblock(self):
        theseUrls=[]
        exitNodeIPs=[]
        response = self.getList("https://check.torproject.org", ["/exit-addresses"])
        if len(response[0]) > 0:
            theseLines=response[0].decode().split("\n")
        else:
            return
        for j in theseLines:
            # Check if the line starts with ExitAddress
            if j.startswith("ExitAddress"):
                # split the whole line by white space
                ip=j.split(sep=" ")[1]
                self.duplicateList.append(ipaddress.IPv4Network(ip))

    # gets called when the file is executed.
    def run(self):

        parser = argparse.ArgumentParser(description="Updates ipsets with blacklist from diverse sources")
        parser.add_argument('-v',
                '--verbose',
                action='store_true',
                help="Enables verbose mode",
                dest="verbose"
            )

        args = parser.parse_args()

        self.verbose = args.verbose

        number_of_ips=0
        if ENABLE_BLUETACK:
            self.bluetack()
        if ENABLE_COUNTRY:
            self.country()
        if ENABLE_TORBLOCK:
            self.torblock()

        self.unifiedList.extend(self.mergeLists(self.duplicateList))
        self.collapsedList=ipaddress.collapse_addresses(self.unifiedList)

        # Check if any of the IPs or subnets are invalid
        stringList=[]
        for i in self.collapsedList:
            if i.is_multicast or i.is_private or i.is_unspecified or i.is_reserved or i.is_loopback or i.is_link_local:
                continue
            stringList.append(str(i))
        

        temporaryFileV4 = tempfile.NamedTemporaryFile()
        temporaryFileV6 = tempfile.NamedTemporaryFile()


        addTemplate = "add {} {}\n"

        temporaryNameV4, temporaryNameV6 = self.deriveNames(
            self.temporaryNameTemplate
            )
        permanentNameV4, permanentNameV6 = self.deriveNames(
            self.permanentNameTemplate
            ) 

        self.writeHeader(temporaryFileV4.file,
            self.generateFileHeader(temporaryNameV4, settype="hash:net"))

        self.writeHeader(temporaryFileV6.file,
            self.generateFileHeader(temporaryNameV6, settype="hash:net", family="inet6"))
        for i in stringList:

            # check if it's IPv4
            if i.find(".") != -1:
                temporaryFileV4.file.write(bytearray(
                    addTemplate.format(temporaryNameV4, i), 'utf-8')
                )
                number_of_ips += 1
            # else it's IPv6
            else:
                temporaryFileV6.file.write(bytearray(
                    addTemplate.format(temporaryNameV6, i), 'utf-8')
                )
                number_of_ips += 1

        temporaryFileV4.file.flush()
        temporaryFileV6.file.flush()
        # IPv4
        # load the new records into the new set
        self.restoreFile(temporaryFileV4.name)

        # swap the set
        self.swapSets(permanentNameV4, temporaryNameV4)
        
        # destroy the old set
        self.destroySet(temporaryNameV4)

        # IPv6 
        # load the new records into the new set
        self.restoreFile(temporaryFileV6.name)

        # swap the set
        self.swapSets(permanentNameV6, temporaryNameV6)
        
        # destroy the old set
        self.destroySet(temporaryNameV6)

        if self.verbose:
            print ("Loaded {} IPs into the sets".format(number_of_ips))
if __name__ == '__main__':
    peerguardian = pgPy()
    peerguardian.run()