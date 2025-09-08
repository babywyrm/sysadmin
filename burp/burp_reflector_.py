#!/usr/bin/env python3
"""
Burp Extension – Refactored Scanner - (..beta..)
Detects:
  • XSS via reflected headers (e.g. Referer) or parameters
  • Pipe injection via '|'

Features:
  • Configurable payloads
  • Core detection logic testable outside Burp
  • Unified clean implementation
"""

import re
import logging
from array import array
from burp import IBurpExtender, IScannerCheck, IScanIssue, IParameter

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
XSS_PAYLOADS = [
    "\"'>TTT",
    "javascript:alert(1)",
    "<svg/onload=alert(1337)>"
]

PIPE_ERROR = "Unexpected pipe"

SUPPORT_PARAMETER_TYPES = [
    IParameter.PARAM_URL,
    IParameter.PARAM_BODY,
    IParameter.PARAM_MULTIPART_ATTR,
    IParameter.PARAM_JSON,
    IParameter.PARAM_XML,
    IParameter.PARAM_XML_ATTR,
]

# Logging to Burp console
logging.basicConfig(level=logging.INFO, format="[Scanner] %(message)s")


# -------------------------------------------------------------------
# Core Logic (unit-testable)
# -------------------------------------------------------------------
def find_reflections(payload: str, response: str):
    """Return list of indices where payload is reflected in the response."""
    return [m.start() for m in re.finditer(re.escape(payload), response)]


def check_header_reflection(request: str, response: str, header_name: str, payload: str):
    """Check if a given header value is reflected in the response."""
    headers, _, _ = request.partition("\r\n\r\n")
    for line in headers.splitlines():
        if line.lower().startswith(header_name.lower() + ":"):
            val = line.split(":", 1)[1].strip()
            if val and val in response:
                return {
                    "vector": f"Header {header_name}",
                    "payload": payload,
                    "reflected_at": find_reflections(payload, response),
                }
    return None


def check_param_reflection(param_name: str, param_value: str, response: str, payload: str):
    """Check if a parameter value is reflected in the response."""
    if param_value not in response:
        return None
    return {
        "vector": f"Parameter {param_name}",
        "payload": payload,
        "reflected_at": find_reflections(payload, response),
    }


def check_pipe_injection(response: str, payload: str = "|", error_str: str = PIPE_ERROR):
    """Check if injecting a pipe character leads to an error response."""
    if error_str in response:
        return {
            "vector": "Pipe injection",
            "payload": payload,
            "error": error_str,
            "reflected_at": find_reflections(error_str, response),
        }
    return None


# -------------------------------------------------------------------
# Custom Issue
# -------------------------------------------------------------------
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Firm"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService


# -------------------------------------------------------------------
# Burp Extension
# -------------------------------------------------------------------
class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Refactored XSS & Injection Scanner")
        callbacks.registerScannerCheck(self)
        logging.info("Extension registered")

    # ----------------------------
    # Passive Scanner
    # ----------------------------
    def doPassiveScan(self, baseRequestResponse):
        req_str = self._helpers.bytesToString(baseRequestResponse.getRequest())
        res_bytes = baseRequestResponse.getResponse()
        if not res_bytes:
            return None
        res_str = self._helpers.bytesToString(res_bytes)

        req_info = self._helpers.analyzeRequest(baseRequestResponse)
        params = req_info.getParameters()
        issues = []

        # Only check HTML-like responses
        headers = self._helpers.analyzeResponse(res_bytes).getHeaders()
        content_type = next((h for h in headers if "content-type:" in h.lower()), "")
        if "html" not in content_type.lower():
            return None

        # Check headers (e.g. Referer, User-Agent)
        for header_name in ["referer", "user-agent"]:
            for payload in XSS_PAYLOADS:
                hdr_issue = check_header_reflection(req_str, res_str, header_name, payload)
                if hdr_issue:
                    matches = self._get_matches(res_bytes, payload.encode())
                    issues.append(
                        CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            req_info.getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                            f"XSS via {hdr_issue['vector']}",
                            f"Reflected payload '{payload}' via {hdr_issue['vector']}",
                            "High",
                        )
                    )

        # Check parameters
        for param in params:
            if param.getType() not in SUPPORT_PARAMETER_TYPES:
                continue
            value = self._helpers.urlDecode(param.getValue())
            for payload in XSS_PAYLOADS:
                param_issue = check_param_reflection(param.getName(), value, res_str, payload)
                if param_issue:
                    matches = self._get_matches(res_bytes, payload.encode())
                    issues.append(
                        CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            req_info.getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                            f"XSS via {param.getName()}",
                            f"Reflected payload '{payload}' in parameter {param.getName()}",
                            "High",
                        )
                    )

        return issues or None

    # ----------------------------
    # Active Scanner
    # ----------------------------
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        checkReq = insertionPoint.buildRequest(b"|")
        checkResp = self._callbacks.makeHttpRequest(
            baseRequestResponse.getHttpService(), checkReq
        )
        res_bytes = checkResp.getResponse()
        if not res_bytes:
            return None
        res_str = self._helpers.bytesToString(res_bytes)

        issue = check_pipe_injection(res_str)
        if issue:
            matches = self._get_matches(res_bytes, PIPE_ERROR.encode())
            return [
                CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkResp, None, matches)],
                    "Pipe Injection",
                    f"Submitting '|' triggered error: {PIPE_ERROR}",
                    "High",
                )
            ]
        return None

    # ----------------------------
    # Helpers
    # ----------------------------
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0

    def _get_matches(self, response, match):
        matches, start, reslen, matchlen = [], 0, len(response), len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array("i", [start, start + matchlen]))
            start += matchlen
        return matches
