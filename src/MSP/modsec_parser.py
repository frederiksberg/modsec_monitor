import json
import re
from datetime import datetime
from mmap import mmap, ACCESS_READ
from typing import Dict, List, Any

DATEFORMAT_IN = "%d/%b/%Y:%H:%M:%S"
DATEFORMAT_OUT = "%d-%m-%Y %H:%M:%S"

class Vuln:
    def __init__(self,
        id : int,
        description : str
    ):
        self.id = id
        self.desc = description

    def ToDict(self) -> Dict:
        return {
            "id": self.id,
            "description": self.desc
        }

    def __str__(self) -> str:
        return json.dumps(self.ToDict(), indent=4)


class Request:
    def __init__(self,
        uri : str,
        host : str,
        method : str,
        protocol : str,
        timestamp : datetime,
        result : str,
        audit_file : str = None
        ):
        self.uri = uri
        self.host = host
        self.method = method
        self.protocol = protocol
        self.ts = timestamp
        self.result = result
        self.vulns = []

        if audit_file is not None:
            self.parse(audit_file)

    def parse(self, file : str) -> None:
        self.vulns = []
        try:
            with open(file, "r") as fd:
                with mmap(fd.fileno(), 0, access=ACCESS_READ) as mm:
                    # Search for header using memory mapping
                    h = mm.find(b"---H--")

                    if h == -1:
                        raise IOError("Invalid file format")

                    # Compile the regular expressions
                    rid = re.compile(r"(?<=\[id \")\d+")
                    rdesc = re.compile(r"(?<=ModSecurity: ).*(?= \[file)")

                    # Match lambda, for performing the matching
                    def match(line, p):
                        m = p.search(line)
                        if m is None: return "-1"
                        else: return m.group()

                    # Seek to the found header
                    mm.seek(h)

                    # Define macro for correctly decoding a line of input
                    def pop(): return mm.readline().decode("utf-8").replace("\n", "")

                    # Pop the first line
                    line = pop()
                    line = pop()

                    # Go through the section until we hit an empty line
                    while line:
                        # Find the ID and parse it as an int
                        id = int(match(line, rid))

                        # Extract the description
                        desc = match(line, rdesc)

                        # Add new Vuln object to list
                        self.vulns.append(
                            Vuln(id, desc)
                        )

                        line = pop()
        except:
            raise IOError("An error occured while parsing an audit file!")

    def ToDict(self) -> Dict:
        return {
            "host": self.host,
            "uri": self.uri,
            "method": self.method,
            "protocol": self.protocol,
            "timestamp": self.ts.strftime(DATEFORMAT_OUT),
            "result": self.result,
            "vulns" : [v.ToDict() for v in self.vulns]
        }

    def __str__(self) -> str:
        return json.dumps(self.ToDict(), indent=4)


class Audit:
    def __init__(self, audit_log : str):
        self.reqs = []

        self.Parse(audit_log)

    def Parse(self, log_content : str) -> None:
        self.reqs = []
        try:
            for line in log_content.split("\n"):
                if len(line) > 0:
                    self.reqs.append(
                        self.ParseUnit(line)
                    )

        except:
            raise IOError("An error occured while parsing log file!")

    def ParseUnit(self, line : str) -> Request:
        try:
            s = line.replace("[", "").replace('"', "").split(" ")

            return Request(
                s[6],
                s[0],
                s[5],
                s[7],
                datetime.strptime(s[3], DATEFORMAT_IN),
                s[8],
                s[-4]
            )
        except:
            raise ValueError(f"Error while parsing {s}")

    def ToDict(self) -> Dict:
        return {
            "requests": [r.ToDict() for r in self.reqs]
        }

    def ToJSON(self) -> str:
        return json.dumps(self.ToDict())

    def __str__(self) -> str:
        return json.dumps(self.ToDict(), indent=4)

if __name__ == "__main__":
    content = ""
    with open("test.log", "r") as fd:
        content = fd.read()
    a = Audit(content)

    print(a)
    print(a.ToJSON())
