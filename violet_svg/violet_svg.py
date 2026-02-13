# violet_svg/violet_svg.py
import os
import sys
import warnings
import base64
import copy
import json
import hashlib
import logging
import subprocess
import glob
import regex
from collections import Counter

# We'll prefer re2 if installed, otherwise fallback to re
try:
    import re2 as re
except ImportError:
    import re

import magic
import imagehash
from PIL import Image
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

logger = logging.getLogger(__name__)

regex_is_awesome = {}

regex_is_awesome["http_base64_in_script"] = re.compile(
    r"\b(?:h(?:0(?:V(?:F(?:B[Tz]O|A6)|H(?:B[Tz]O|A6))|d(?:F(?:B[Tz]O|A6)|H(?:B[Tz]O|A6)))"
    r"|U(?:V(?:F(?:B[Tz]O|A6)|H(?:B[Tz]O|A6))|d(?:F(?:B[Tz]O|A6)|H(?:B[Tz]O|A6))))"
    r"|S(?:FR(?:0(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))|U(?:U(?:[FH]M6|D)|c(?:[FH]M6|D)))"
    r"|HR(?:0(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))|U(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))))"
    r"|a(?:FR(?:0(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))|U(?:U(?:[FH]M6|D)|c(?:[FH]M6|D)))"
    r"|HR(?:0(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))|U(?:U(?:[FH]M6|D)|c(?:[FH]M6|D))))"
    r"|I(?:V(?:FR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O))|HR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O)))"
    r"|d(?:FR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O))|HR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O))))"
    r"|o(?:V(?:FR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O))|HR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O)))"
    r"|d(?:FR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O))|HR(?:Q(?:[Uc]z|O)|w(?:[Uc]z|O)))))"
)
regex_is_awesome["eval"] = re.compile(r"\beval\b", re.I)
regex_is_awesome["preventdefault"] = re.compile(r"(?:\x2e|\b)preventDefault\b", re.I)
regex_is_awesome["fromcharcode"] = re.compile(r"(?:\x2e|\b)fromCharCode\b", re.I)
regex_is_awesome["charcodeat"] = re.compile(r"(?:\x2e|\b)charCodeAt\b", re.I)
regex_is_awesome["replace"] = re.compile(r"(?:\x2e|\b)replace\b", re.I)
regex_is_awesome["concat"] = re.compile(r"(?:\x2e|\b)concat\b", re.I)
regex_is_awesome["long_hex_string"] = re.compile(r"(?P<q>[\x22\x27`])[A-F0-9]{40,}(?P=q)", re.I)
regex_is_awesome["long_b64_string"] = re.compile(
    r"[\x22\x27`](?=[A-Za-z0-9+/]{0,80}(?:[a-z][0-9][A-Z]|[A-Z][0-9][a-z]))(?=[A-Za-z0-9+/]{0,80}[a-z][A-Z][a-z])(?=[A-Za-z0-9+/]{0,80}[A-Za-z0-9]\/)(?=[A-Za-z0-9+/]{0,80}[A-Za-z0-9]\+)(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?[\x22\x27`]"
)
regex_is_awesome["two_for_one_match"] = re.compile(r"\.match\(\/\.\{1,2\}\/g", re.I)
regex_is_awesome["split"] = re.compile(r"(?:\x2e|\b)split\b", re.I)
regex_is_awesome["atob"] = re.compile(r"\batob\b", re.I)
regex_is_awesome["btoa"] = re.compile(r"\bbtoa\b", re.I)
regex_is_awesome["unescape"] = re.compile(r"\bunescape\b", re.I)
regex_is_awesome["escape"] = re.compile(r"\bescape\b", re.I)
regex_is_awesome["decodeuri"] = re.compile(r"\bdecodeURI\b", re.I)
regex_is_awesome["encodeuri"] = re.compile(r"\bencodeURI\b", re.I)
regex_is_awesome["decodeuricomponent"] = re.compile(r"\bdecodeURIComponent\b", re.I)
regex_is_awesome["encodeuricomponent"] = re.compile(r"\bencodeURIComponent\b", re.I)
regex_is_awesome["document_write"] = re.compile(r"\bdocument\s*\.\s*write\b", re.I | re.S)
regex_is_awesome["document_writeln"] = re.compile(r"\bdocument\s*\.\s*writeln\b", re.I | re.S)
regex_is_awesome["document_open"] = re.compile(r"\bdocument\s*\.\s*open\b", re.I | re.S)
regex_is_awesome["document_createelement"] = re.compile(r"\bdocument\s*\.\s*createElement\b", re.I | re.S)
regex_is_awesome["window_location"] = re.compile(r"\bwindow\s*\.\s*location\b", re.I | re.S)
regex_is_awesome["contextmenu"] = re.compile(r"\bcontextmenu\b", re.I)
regex_is_awesome["ctrlkey"] = re.compile(r"(?:\x2e|\b)ctrlKey\b", re.I)
regex_is_awesome["shiftkey"] = re.compile(r"(?:\x2e|\b)shiftKey\b", re.I)
regex_is_awesome["altkey"] = re.compile(r"(?:\x2e|\b)altKey\b", re.I)
regex_is_awesome["metakey"] = re.compile(r"(?:\x2e|\b)metaKey\b", re.I)
regex_is_awesome["keycode"] = re.compile(r"(?:\x2e|\b)keyCode\b", re.I)
regex_is_awesome["magic85"] = re.compile(r"===\s*85\b", re.I)
regex_is_awesome["magic123"] = re.compile(r"===\s*123\b", re.I)
regex_is_awesome["magic73"] = re.compile(r"===\s*73\b", re.I)
regex_is_awesome["magic74"] = re.compile(r"===\s*74\b", re.I)
regex_is_awesome["join"] = re.compile(r"(?:\x2e|\b)join\b", re.I)
regex_is_awesome["map"] = re.compile(r"(?:\x2e|\b)map\b", re.I)
regex_is_awesome["filter"] = re.compile(r"(?:\x2e|\b)filter\b", re.I)
regex_is_awesome["reduce"] = re.compile(r"(?:\x2e|\b)reduce\b", re.I)
regex_is_awesome["slice"] = re.compile(r"(?:\x2e|\b)slice\b", re.I)
regex_is_awesome["domcontentloaded"] = re.compile(r"domcontentloaded", re.I)
regex_is_awesome["createelementns"] = re.compile(r"createelementns", re.I)
regex_is_awesome["blob"] = re.compile(r"new\s*blob", re.I | re.S)
regex_is_awesome["click"] = re.compile(r"(?:\x2e|\b)click\b", re.I)
regex_is_awesome["appendchild"] = re.compile(r"(?:\x2e|\b)appendchild\b", re.I)
regex_is_awesome["createobjecturl"] = re.compile(r"(?:\x2e|\b)createobjecturl\b", re.I)
regex_is_awesome["revokeobjecturl"] = re.compile(r"(?:\x2e|\b)revokeobjecturl\b", re.I)
regex_is_awesome["insertbefore"] = re.compile(r"(?:\x2e|\b)insertbefore\b", re.I)
regex_is_awesome["removechild"] = re.compile(r"(?:\x2e|\b)removechild\b", re.I)
regex_is_awesome["addeventlistener"] = re.compile(r"(?:\x2e|\b)addeventlistener\b", re.I)
regex_is_awesome["clipboardwritetext"] = re.compile(r"clipboard\s*\.\s*writetext", re.I | re.S)
regex_is_awesome["settimeout"] = re.compile(r"\bsetTimeout\b", re.I)
regex_is_awesome["setinterval"] = re.compile(r"\bsetInterval\b", re.I)
regex_is_awesome["setimmediate"] = re.compile(r"\bsetImmediate\b", re.I)
regex_is_awesome["parseint"] = re.compile(r"\bparseint\b", re.I)

data_url_pattern = re.compile(r"^data:([^;]+)?(;[^,]+)?,(.*)$", re.IGNORECASE)
# Robust CDATA wrapper that handles complete and incomplete CDATA sections
cdata_wrapper = re.compile(r"<\s*!\s*\[\s*CDATA\s*\[\s*(.*?)\s*\]\s*\]\s*>", re.DOTALL | re.IGNORECASE)
# Fallback for incomplete CDATA (missing end tag)
cdata_start_only = re.compile(r"<\s*!\s*\[\s*CDATA\s*\[\s*", re.IGNORECASE)
invisible_chars_re = regex.compile(r"[\p{Cf}\uFFA0\u3164]+")
wide_svg_tag_re = re.compile(rb"<\x00?s\x00?v\x00?g", re.I)
event_disabled = re.compile(r"(?:^\s*return\s*false|event\.preventdefault)", re.I | re.S)

SVG_ELEMENT_CATEGORIES = {
    "structural": {"svg", "g", "defs", "symbol", "use", "image", "switch", "marker", "a"},
    "shapes": {"rect", "circle", "ellipse", "line", "polyline", "polygon", "path"},
    "descriptive": {"desc", "title", "metadata"},
    "text": {"text", "tspan", "textpath", "tref"},
    "gradient_and_paint": {"lineargradient", "radialgradient", "stop", "pattern", "mesh", "hatch"},
    "filter_and_masking": {
        "clippath",
        "mask",
        "filter",
        "feblend",
        "fecolormatrix",
        "fecomponenttransfer",
        "fecomposite",
        "feconvolvematrix",
        "fediffuselighting",
        "fedisplacementmap",
        "fedropshadow",
        "feflood",
        "fefunca",
        "fefuncb",
        "fefuncg",
        "fefuncr",
        "fegaussianblur",
        "feimage",
        "femerge",
        "femergenode",
        "femorphology",
        "feoffset",
        "fespecularlighting",
        "fetile",
        "feturbulence",
        "color-profile",
    },
    "animation": {"animate", "animatetransform", "animatemotion", "set", "mpath", "animatecolor"},
    "other": {"foreignobject", "script", "style", "solidcolor"},
}

SVG_ATTRIBUTE_CATEGORIES = {
    "core_global": {"id", "xml:base", "xml:lang", "xml:space", "tabindex", "xmlns", "xmlns:xlink"},
    "events": {
        "onabort",
        "onauxclick",
        "onblur",
        "oncancel",
        "oncanplay",
        "oncanplaythrough",
        "onchange",
        "onclick",
        "onclose",
        "oncontextmenu",
        "oncopy",
        "oncut",
        "ondblclick",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onemptied",
        "onended",
        "onerror",
        "onfocus",
        "onfocusin",
        "onfocusout",
        "onformdata",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onmousedown",
        "onmouseenter",
        "onmouseleave",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpointercancel",
        "onpointerdown",
        "onpointerenter",
        "onpointerleave",
        "onpointermove",
        "onpointerout",
        "onpointerover",
        "onpointerrawupdate",
        "onpointerup",
        "onratechange",
        "onreset",
        "onresize",
        "onscroll",
        "onseeked",
        "onseeking",
        "onselect",
        "onsort",
        "onstalled",
        "onsubmit",
        "onsuspend",
        "ontimeupdate",
        "ontoggle",
        "onvolumechange",
        "onwaiting",
        "onwheel",
        "ontouchstart",
        "ontouchend",
        "ontouchmove",
        "ontouchcancel",
        "ongotpointercapture",
        "onlostpointercapture",
        "onbegin",
        "onrepeat",
        "onend",
    },
    "presentation": {
        "class",
        "style",
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-opacity",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-miterlimit",
        "stroke-dasharray",
        "stroke-dashoffset",
        "color",
        "color-interpolation",
        "color-interpolation-filters",
        "opacity",
        "display",
        "visibility",
        "pointer-events",
        "shape-rendering",
        "text-rendering",
        "image-rendering",
        "clip",
        "clip-rule",
    },
    "coordinate_geometry": {"x", "y", "dx", "dy", "x1", "y1", "x2", "y2", "width", "height", "rx", "ry", "cx", "cy", "r", "d", "points"},
    "transform_coordinate": {"transform", "viewbox", "preserveaspectratio"},
    "text_specific": {
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "text-anchor",
        "letter-spacing",
        "word-spacing",
        "dominant-baseline",
        "alignment-baseline",
        "rotate",
        "textlength",
        "lengthadjust",
    },
    "linking": {"href", "xlink:href", "target", "xlink:type", "xlink:title", "xlink:show", "xlink:actuate"},
    "animation": {
        "attributename",
        "attributetype",
        "begin",
        "dur",
        "end",
        "repeatcount",
        "repeatdur",
        "fill",
        "restart",
        "calcmode",
        "keytimes",
        "keysplines",
        "from",
        "to",
        "by",
        "values",
    },
    "filter_masking": {
        "filter",
        "mask",
        "clip-path",
        "clip-rule",
        "filterunits",
        "primitiveunits",
        "filterres",
        "in",
        "in2",
        "result",
        "stddeviation",
        "flood-color",
        "flood-opacity",
        "surfacescale",
        "specularconstant",
        "specularexponent",
        "xchannelselector",
        "ychannelselector",
    },
    "gradient_pattern": {
        "gradientunits",
        "gradienttransform",
        "spreadmethod",
        "fx",
        "fy",
        "patternunits",
        "patterntransform",
        "patterncontentunits",
        "offset",
        "stop-color",
        "stop-opacity",
    },
    "conditional_processing": {"externalresourcesrequired", "requiredfeatures", "requiredextensions", "systemlanguage"},
}


def find_all_case_insensitive(soup, tag_name):
    """Find all tags matching the given name, case-insensitive.

    This method is more robust against evasion - it checks ALL tags in the document
    and compares their names case-insensitively, rather than trying to guess
    possible case variations.
    """
    target_name_lower = tag_name.lower()
    found_tags = []

    # Get all tags and filter by case-insensitive name comparison
    for tag in soup.find_all():
        if tag.name and tag.name.lower() == target_name_lower:
            found_tags.append(tag)

    return found_tags


def log_invisible_codepoints(text):
    """Collect invisible Unicode codepoints from text."""
    flags = []
    for match in invisible_chars_re.finditer(text):
        for ch in match.group():
            hex_value = f"{ord(ch):04X}"
            flags.append(f"svg_unicode_invisible_{hex_value}")
    return flags


def compress_invisible_flags(flags_list):
    """Summarize invisible char flags."""
    c = Counter(flags_list)
    unique_flags = sorted(c.keys())
    return unique_flags, dict(c)


def hash_list(strings):
    """Produce a SHA256 over a list of strings."""
    joined = "\n".join(strings)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def flag_single_script_no_others(soup):
    """Check if there's exactly one <script> and no other elements besides <svg>."""
    scripts = find_all_case_insensitive(soup, "script")
    script_count = len(scripts)
    all_elems = soup.find_all()
    other_elems = [t for t in all_elems if t.name and t.name.lower() not in ("script", "svg")]
    return script_count > 0 and len(other_elems) == 0


def check_fullscreen_foreignobject(soup):
    """Return True if <foreignObject> is 100% width+height."""
    foreign_objects = find_all_case_insensitive(soup, "foreignObject")
    for fo in foreign_objects:
        w = (fo.get("width", "") or "").strip().lower()
        h = (fo.get("height", "") or "").strip().lower()
        if w == "100%" and h == "100%":
            return True
        style_attr = (fo.get("style", "") or "").lower()
        if "width:100" in style_attr and "height:100" in style_attr:
            return True
    return False


def check_iframe_in_foreignobject(soup):
    """Return True if <iframe> is found inside a <foreignObject>."""
    foreign_objects = find_all_case_insensitive(soup, "foreignObject")
    for fo in foreign_objects:
        if fo.find("iframe"):
            return True
    return False


def check_remote_script_in_foreignobject(soup):
    """Return True if remote script sources are found inside <foreignObject>."""
    foreign_objects = find_all_case_insensitive(soup, "foreignObject")
    for fo in foreign_objects:
        # Look for script tags with src attributes
        scripts = find_all_case_insensitive(fo, "script")
        for script in scripts:
            src = script.get("src", "").strip()
            if src:
                # Check if it's a remote URL (starts with http:// or https://)
                if src.lower().startswith(("http://", "https://")):
                    return True
    return False


def check_hidden_foreignobject(soup):
    """Return True if hidden <foreignObject> is found (zero width/height or hidden overflow)."""
    foreign_objects = find_all_case_insensitive(soup, "foreignObject")
    for fo in foreign_objects:
        # Check for zero width or height
        w = (fo.get("width", "") or "").strip().lower()
        h = (fo.get("height", "") or "").strip().lower()
        if w == "0" or h == "0" or w == "0px" or h == "0px":
            return True

        # Check for hidden overflow
        overflow = (fo.get("overflow", "") or "").strip().lower()
        if overflow == "hidden":
            return True

        # Check if hidden via style attribute
        style_attr = (fo.get("style", "") or "").lower()
        if any(hidden_prop in style_attr for hidden_prop in ["width:0", "height:0", "visibility:hidden", "display:none", "overflow:hidden"]):
            return True

        # Check if positioned offscreen
        x = (fo.get("x", "") or "").strip().lower()
        y = (fo.get("y", "") or "").strip().lower()
        if any(coord.startswith("-") for coord in [x, y]):
            return True

    return False


def check_script_in_hidden_foreignobject(soup):
    """Return True if <script> tags are found inside hidden <foreignObject> elements."""
    foreign_objects = find_all_case_insensitive(soup, "foreignObject")
    for fo in foreign_objects:
        # First check if this foreignObject is hidden
        is_hidden = False

        # Check for zero width or height
        w = (fo.get("width", "") or "").strip().lower()
        h = (fo.get("height", "") or "").strip().lower()
        if w == "0" or h == "0" or w == "0px" or h == "0px":
            is_hidden = True

        # Check for hidden overflow
        if not is_hidden:
            overflow = (fo.get("overflow", "") or "").strip().lower()
            if overflow == "hidden":
                is_hidden = True

        # Check if hidden via style attribute
        if not is_hidden:
            style_attr = (fo.get("style", "") or "").lower()
            if any(
                hidden_prop in style_attr for hidden_prop in ["width:0", "height:0", "visibility:hidden", "display:none", "overflow:hidden"]
            ):
                is_hidden = True

        # Check if positioned offscreen
        if not is_hidden:
            x = (fo.get("x", "") or "").strip().lower()
            y = (fo.get("y", "") or "").strip().lower()
            if any(coord.startswith("-") for coord in [x, y]):
                is_hidden = True

        # If this foreignObject is hidden, check for script tags inside it
        if is_hidden:
            scripts = find_all_case_insensitive(fo, "script")
            if scripts:
                return True

    return False


class SVGAnalyzer:
    def __init__(self):
        self.input_path = None
        self.output_dir = None
        self.disable_image_hashes = False
        self.raw = False
        self.is_svg_wide = False

    def analyze_file(self, input_path, output_dir, disable_image_hashes=False, raw=False, boxjs_path=None, boxjs_timeout=20):
        self.input_path = input_path
        self.output_dir = output_dir
        self.disable_image_hashes = disable_image_hashes
        self.raw = raw
        self.boxjs_path = boxjs_path
        self.boxjs_timeout = boxjs_timeout

        os.makedirs(self.output_dir, exist_ok=True)

        with open(self.input_path, "rb") as f:
            raw_bytes = f.read()
            match = wide_svg_tag_re.search(raw_bytes)
            if match:
                logger.info(f"found potential wide <svg> tag: {match.group(0)!r}")
                if match.group(0) == b"<\x00s\x00v\x00g":
                    logger.info("found null bytes in svg tag, removing them")
                    raw_bytes = raw_bytes.replace(b"\x00", b"")
                    self.is_svg_wide = True

        content = raw_bytes.decode("utf-8", errors="ignore")
        results = self.run_analysis(content)
        original_urls = list(set(results["extracted_data"]["urls"]))
        data_urls_info, final_urls = self.extract_and_store_data_urls(original_urls)
        results["extracted_data"]["urls"] = final_urls
        results["data_urls"] = data_urls_info

        if results["extracted_data"]["scripts"]:
            dom_elements = results.get("dom_elements", [])
            dom_js = self._generate_dom_element_js(dom_elements)
            joined_scripts = "\n".join(results["extracted_data"]["scripts"])
            combined = dom_js + "\n" + joined_scripts
            results["extracted_data"]["reconstructed_script"] = combined

            # Write combined script to output dir
            script_path = os.path.join(self.output_dir, "reconstructed_script.js")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(combined)
            logger.info(f"Wrote combined box-js script to: {script_path}")

            # Run box-js if path provided
            if self.boxjs_path:
                boxjs_results = self._run_boxjs(script_path)

                # Check if box-js produced meaningful IOCs
                boxjs_has_results = self._boxjs_has_meaningful_iocs(boxjs_results)

                if not boxjs_has_results:
                    # Static URL extraction fallback
                    static_urls = self._extract_urls_from_script(combined)
                    if static_urls:
                        boxjs_results["static_script_urls"] = static_urls
                        logger.info(f"Static URL extraction found {len(static_urls)} URLs in script")

                    # Promote remote script URLs when box-js found nothing
                    if results.get("has_remote_script_in_foreignobject"):
                        remote_urls = results["extracted_data"].get("urls", [])
                        if remote_urls:
                            boxjs_results["remote_script_urls"] = remote_urls
                            logger.info(f"Promoted {len(remote_urls)} remote script URLs as IOCs")

                results["boxjs_results"] = boxjs_results

        results.pop("dom_elements", None)

        if self.raw:
            results["raw_content"] = content

        return results

    def run_analysis(self, content):
        raw_bytes = content.encode("utf-8", errors="ignore")
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=XMLParsedAsHTMLWarning)
            try:
                # Try XML parser first since SVG is XML (handles CDATA properly)
                soup = BeautifulSoup(content, "xml")
                if not soup.find("svg"):
                    # Fallback to HTML parser if XML doesn't find SVG
                    soup = BeautifulSoup(content, "html.parser")
            except XMLParsedAsHTMLWarning:
                # If XML parser has issues, fallback to HTML parser
                soup = BeautifulSoup(content, "html.parser")

        invisible_flags = log_invisible_codepoints(content)
        unique_flags, counts = compress_invisible_flags(invisible_flags)
        found_invisible_chars = bool(invisible_flags)
        normalized_content = invisible_chars_re.sub("", content)
        total_invisible_chars = sum(counts.values())
        invisible_flags_hash = hash_list(sorted(invisible_flags))
        only_script = flag_single_script_no_others(soup)
        has_fullscreen_fo = check_fullscreen_foreignobject(soup)
        has_iframe_fo = check_iframe_in_foreignobject(soup)
        has_remote_script_fo = check_remote_script_in_foreignobject(soup)
        has_hidden_fo = check_hidden_foreignobject(soup)
        has_script_in_hidden_fo = check_script_in_hidden_foreignobject(soup)
        detail_results = self._analyze_svg_security(soup)
        has_base64_dataurl_script_src = detail_results["has_base64_dataurl_script_src"]
        found_script = bool(detail_results["extracted_data"]["scripts"])
        script_features = {}
        if found_script:
            for name, rgx_pattern in regex_is_awesome.items():
                script_features[name] = False
                for scode in detail_results["extracted_data"]["scripts"]:
                    if rgx_pattern.search(scode):
                        script_features[name] = True
                        break

        lines_for_security = [
            f"HAS_SCRIPT={int(found_script)}",
            f"HAS_BASE64_DATAURL_SCRIPT_SRC={int(has_base64_dataurl_script_src)}",
            f"STRUCT_COMPOSITE={detail_results['composite_hash']}",
            f"WIDE_SVG_TAG={int(self.is_svg_wide)}",
            f"INVISIBLE_PRESENT={int(found_invisible_chars)}",
            f"INVISIBLE_FLAGS_HASH={invisible_flags_hash}",
            f"ONLY_SCRIPT={int(only_script)}",
            f"FULLSCREEN_FOREIGNOBJECT={int(has_fullscreen_fo)}",
            f"IFRAME_IN_FOREIGNOBJECT={int(has_iframe_fo)}",
        ]
        security_input = "\n".join(lines_for_security)
        security_composite_hash = hashlib.sha256(security_input.encode("utf-8")).hexdigest()

        svg_w = detail_results["svg_metadata"].get("width", "unknown")
        svg_h = detail_results["svg_metadata"].get("height", "unknown")
        lines_for_security_dims = lines_for_security + [f"SVG_WIDTH={svg_w}", f"SVG_HEIGHT={svg_h}"]
        security_composite_hash_dimensions = hashlib.sha256("\n".join(lines_for_security_dims).encode("utf-8")).hexdigest()

        lines_for_security_script_features = lines_for_security + [f"SCRIPT_FEATURES={script_features}"]
        security_composite_hash_script_features_v1 = hashlib.sha256("\n".join(lines_for_security_script_features).encode("utf-8")).hexdigest()

        results = {
            "has_script": found_script,
            "has_on_trigger": detail_results["has_on_trigger"],
            "svg_metadata": detail_results["svg_metadata"],
            "element_presence": detail_results["element_presence"],
            "element_counts": detail_results["element_counts"],
            "attribute_presence": detail_results["attribute_presence"],
            "attribute_counts": detail_results["attribute_counts"],
            "presence_hashes": detail_results["presence_hashes"],
            "count_hashes": detail_results["count_hashes"],
            "composite_hash": detail_results["composite_hash"],
            "is_svg_wide": self.is_svg_wide,
            "found_invisible_chars": found_invisible_chars,
            "normalized_content_length": len(normalized_content),
            "original_content_length": len(content),
            "invisible_flags_hash": invisible_flags_hash,
            "invisible_flags_unique": unique_flags,
            "invisible_flags_counts": counts,
            "invisible_chars_total": total_invisible_chars,
            "only_script": only_script,
            "has_fullscreen_foreignobject": has_fullscreen_fo,
            "has_iframe_in_foreignobject": has_iframe_fo,
            "has_remote_script_in_foreignobject": has_remote_script_fo,
            "has_hidden_foreignobject": has_hidden_fo,
            "has_script_in_hidden_foreignobject": has_script_in_hidden_fo,
            "has_script": found_script,
            "has_base64_dataurl_script_src": has_base64_dataurl_script_src,
            "has_disabled_onevent": detail_results["has_disabled_onevent"],
            "disabled_onevents": detail_results["disabled_onevents"],
            "script_features": script_features,
            "security_composite_hash": security_composite_hash,
            "security_composite_hash_dimensions": security_composite_hash_dimensions,
            "security_composite_hash_script_features_v1": security_composite_hash_script_features_v1,
            "extracted_data": detail_results["extracted_data"],
            "dom_elements": detail_results.get("dom_elements", []),
        }

        return results

    def _analyze_svg_security(self, soup):
        svg_metadata = {}
        text_content = []
        extracted_urls = []
        extracted_scripts = []
        has_on_trigger = False
        has_disabled_onevent = False
        disabled_onevents = []
        has_base64_dataurl_script_src = False
        dom_elements = []

        root_svg = soup.find("svg")
        if root_svg:
            svg_metadata["width"] = root_svg.get("width")
            svg_metadata["height"] = root_svg.get("height")
            svg_metadata["viewBox"] = root_svg.get("viewbox")
            svg_metadata["preserveAspectRatio"] = root_svg.get("preserveaspectratio")
            svg_metadata["version"] = root_svg.get("version")
            svg_metadata["baseProfile"] = root_svg.get("baseprofile")

        for svg_el in find_all_case_insensitive(soup, "svg"):
            for txt_node in find_all_case_insensitive(svg_el, "text"):
                txt_val = txt_node.get_text(" ", strip=True)
                if txt_val:
                    text_content.append(txt_val)

        element_presence = {cat: set() for cat in SVG_ELEMENT_CATEGORIES}
        element_presence["unknown"] = set()
        element_counts = {cat: Counter() for cat in SVG_ELEMENT_CATEGORIES}
        element_counts["unknown"] = Counter()

        attribute_presence = {cat: set() for cat in SVG_ATTRIBUTE_CATEGORIES}
        attribute_presence["unknown"] = set()
        attribute_counts = {cat: Counter() for cat in SVG_ATTRIBUTE_CATEGORIES}
        attribute_counts["unknown"] = Counter()

        elem_to_cat = {}
        for cat, elems in SVG_ELEMENT_CATEGORIES.items():
            for e in elems:
                elem_to_cat[e.lower()] = cat

        attr_to_cat = {}
        for cat, attrs in SVG_ATTRIBUTE_CATEGORIES.items():
            for a in attrs:
                attr_to_cat[a.lower()] = cat

        possible_url_attrs = {"href", "xlink:href", "src", "xlink:src"}

        for tag in soup.find_all():
            tag_name = (tag.name or "").lower()
            cat = elem_to_cat.get(tag_name, "unknown")
            element_presence[cat].add(tag_name)
            element_counts[cat][tag_name] += 1

            if tag_name != "script" and tag_name != "[document]":
                elem_id = tag.attrs.get("id")
                elem_text = tag.get_text(" ", strip=True)
                elem_attrs = {}
                for attr_name, attr_value in tag.attrs.items():
                    if isinstance(attr_value, list):
                        elem_attrs[attr_name] = " ".join(attr_value)
                    else:
                        elem_attrs[attr_name] = str(attr_value)
                dom_elements.append({
                    "tag_name": tag_name,
                    "id": elem_id,
                    "text_content": elem_text,
                    "attrs": elem_attrs,
                })

            if tag_name == "script":
                script_text = tag.get_text(strip=True)
                if script_text:
                    # First try to extract content from complete CDATA wrapper
                    cdata_matches = cdata_wrapper.findall(script_text)
                    if cdata_matches:
                        # Use content inside CDATA wrapper(s)
                        script_text = "\n".join(cdata_matches)
                    else:
                        # Fallback: remove incomplete CDATA start tag if present
                        script_text = cdata_start_only.sub("", script_text)
                    extracted_scripts.append(script_text)

                # Check for script sources in both src and xlink:href attributes
                script_src = None
                if "src" in tag.attrs:
                    script_src = tag["src"]
                elif "xlink:href" in tag.attrs:
                    script_src = tag["xlink:href"]

                if script_src:
                    extracted_urls.append(script_src)

                    m = data_url_pattern.match(script_src.strip())
                    if m:
                        rest_params = m.group(2) or ""
                        data_part = m.group(3)
                        if "base64" in rest_params.lower():
                            has_base64_dataurl_script_src = True
                            try:
                                raw_bytes = base64.b64decode(data_part, validate=True)
                            except Exception as e:
                                # Try with padding if needed
                                try:
                                    padded_data = data_part + '=' * (4 - len(data_part) % 4) if len(data_part) % 4 else data_part
                                    raw_bytes = base64.b64decode(padded_data, validate=True)
                                except Exception:
                                    raw_bytes = data_part.encode("utf-8", errors="replace")
                            try:
                                if b"\x00" in raw_bytes:
                                    raw_bytes = base64.b64decode(raw_bytes).decode("UTF-16")
                            except:
                                pass
                            script_decoded = raw_bytes.decode("utf-8", errors="replace")
                            extracted_scripts.append(script_decoded)

            for attr_name, attr_value in tag.attrs.items():
                lower_attr_name = attr_name.lower()
                if lower_attr_name in SVG_ATTRIBUTE_CATEGORIES["events"]:
                    if event_disabled.search(attr_value):
                        has_disabled_onevent = True
                        disabled_onevents.append(lower_attr_name)
                    else:
                        # Only add non-disabled event handlers to extracted_scripts
                        extracted_scripts.append(attr_value)
                    has_on_trigger = True

            for full_attr_name, attr_value in tag.attrs.items():
                unified_attr = full_attr_name.split(":", 1)[-1].lower()
                attr_cat = attr_to_cat.get(unified_attr, "unknown")
                attribute_presence[attr_cat].add(unified_attr)
                attribute_counts[attr_cat][unified_attr] += 1

                if unified_attr in possible_url_attrs:
                    # For script tags, we handle src/xlink:href separately above
                    if tag_name != "script":
                        extracted_urls.append(attr_value)

                if unified_attr == "style":
                    found_in_style = re.findall(r'url\s*\(\s*["\']?([^"\')]+)', attr_value, flags=re.IGNORECASE)
                    extracted_urls.extend(found_in_style)

        for style_tag in find_all_case_insensitive(soup, "style"):
            style_content = style_tag.get_text()
            found_block = re.findall(r'url\s*\(\s*["\']?([^"\')]+)', style_content, flags=re.IGNORECASE)
            extracted_urls.extend(found_block)

        presence_hashes = {}
        count_hashes = {}

        for cat, pres_set in element_presence.items():
            sorted_presence = sorted(pres_set)
            presence_hashes[f"element:{cat}:presence"] = hash_list(sorted_presence)

            cnt = element_counts[cat]
            sorted_counts = [f"{k}:{v}" for k, v in sorted(cnt.items())]
            count_hashes[f"element:{cat}:count"] = hash_list(sorted_counts)

        for cat, pres_set in attribute_presence.items():
            sorted_presence = sorted(pres_set)
            presence_hashes[f"attribute:{cat}:presence"] = hash_list(sorted_presence)

            cnt = attribute_counts[cat]
            sorted_counts = [f"{k}:{v}" for k, v in sorted(cnt.items())]
            count_hashes[f"attribute:{cat}:count"] = hash_list(sorted_counts)

        all_keys = sorted(list(presence_hashes.keys()) + list(count_hashes.keys()))
        composite_input = []
        for key in all_keys:
            if key in presence_hashes:
                composite_input.append(key + "=" + presence_hashes[key])
            else:
                composite_input.append(key + "=" + count_hashes[key])
        composite_str = "\n".join(composite_input)
        composite_hash = hashlib.sha256(composite_str.encode("utf-8")).hexdigest()

        return {
            "svg_metadata": svg_metadata,
            "element_presence": {k: sorted(list(v)) for k, v in element_presence.items()},
            "element_counts": {k: dict(v) for k, v in element_counts.items()},
            "attribute_presence": {k: sorted(list(v)) for k, v in attribute_presence.items()},
            "attribute_counts": {k: dict(v) for k, v in attribute_counts.items()},
            "presence_hashes": presence_hashes,
            "count_hashes": count_hashes,
            "composite_hash": composite_hash,
            "has_on_trigger": has_on_trigger,
            "has_disabled_onevent": has_disabled_onevent,
            "disabled_onevents": disabled_onevents,
            "has_base64_dataurl_script_src": has_base64_dataurl_script_src,
            "extracted_data": {
                "urls": extracted_urls,
                "scripts": extracted_scripts,
                "text": text_content,
            },
            "dom_elements": dom_elements,
        }

    def _generate_dom_element_js(self, dom_elements):
        """Generate box-js compatible JS declarations for SVG DOM elements.

        Produces var ids, data, attrs (for getElementById) and
        var tagNameMap (for getElementsByTagName) matching the format
        expected by box-js boilerplate.js.
        """
        ids_arrays = []
        data_arrays = []
        attrs_dicts = []
        tag_name_map = {}

        for elem in dom_elements:
            tag = elem["tag_name"]
            text = elem["text_content"]

            # Collect for tagNameMap (all elements, grouped by tag)
            if tag not in tag_name_map:
                tag_name_map[tag] = []
            tag_name_map[tag].append(text)

            # Collect for ids/data/attrs (only elements with an id)
            elem_id = elem["id"]
            if elem_id:
                ids_arrays.append([ord(c) for c in elem_id])
                data_arrays.append([ord(c) for c in text])
                attrs_dicts.append(elem["attrs"])

        lines = []
        lines.append("var ids = " + json.dumps(ids_arrays) + ";")
        lines.append("var data = " + json.dumps(data_arrays) + ";")
        lines.append("var attrs = " + json.dumps(attrs_dicts) + ";")
        lines.append("var tagNameMap = " + json.dumps(tag_name_map) + ";")

        return "\n".join(lines)

    @staticmethod
    def _boxjs_has_meaningful_iocs(boxjs_results):
        """Check whether box-js produced IOCs beyond the default Sample Name."""
        if boxjs_results.get("error"):
            return False
        iocs = boxjs_results.get("iocs", [])
        meaningful = [i for i in iocs if i.get("type") != "Sample Name"]
        if meaningful:
            return True
        urls = boxjs_results.get("urls", [])
        if urls:
            return True
        return False

    @staticmethod
    def _extract_urls_from_script(script_content):
        """Extract URLs from script content via regex as a fallback when
        box-js dynamic analysis fails."""
        url_re = re.compile(r'https?://[^\s\x22\x27`<>\\\x29\x5d]+')
        matches = url_re.findall(script_content)
        seen = set()
        urls = []
        for url in matches:
            url = url.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def _run_boxjs(self, script_path):
        """Run box-js on the given script and return parsed results.

        Returns a dict with 'iocs', 'urls', and 'output_dir' on success,
        or 'error' on failure.
        """
        boxjs_out = os.path.join(self.output_dir, "box_js_out")
        os.makedirs(boxjs_out, exist_ok=True)

        cmd = [
            self.boxjs_path, script_path,
            f"--output-dir={boxjs_out}",
            "--prepended-code=default",
            "--fake-download",
            "--encoding=utf8",
            "--preprocess",
            "--rewrite-loops",
            "--activex-as-ioc",
            "--no-kill",
            "--no-shell-error",
            f"--timeout={self.boxjs_timeout}",
            "--loglevel=debug",
            "--extract-conditional-code",
            "--ignore-wscript.quit",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.boxjs_timeout + 30,
            )
            logger.info(f"box-js stdout:\n{result.stdout}")
            if result.stderr:
                logger.debug(f"box-js stderr:\n{result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"box-js timed out after {self.boxjs_timeout + 30} seconds")
            return {"error": f"box-js timed out after {self.boxjs_timeout + 30} seconds"}
        except FileNotFoundError:
            logger.error(f"box-js binary not found at {self.boxjs_path}")
            return {"error": f"box-js binary not found at {self.boxjs_path}"}
        except Exception as e:
            logger.error(f"box-js execution failed: {e}")
            return {"error": str(e)}

        # Find the .results directory — box-js creates {filename}.results/
        # and appends .1.results, .2.results, etc. on reruns
        script_basename = os.path.basename(script_path)
        results_pattern = os.path.join(boxjs_out, f"{script_basename}*.results")
        results_dirs = sorted(glob.glob(results_pattern))

        if not results_dirs:
            logger.warning("box-js produced no .results directory")
            return {"error": "no .results directory produced"}

        results_dir = results_dirs[-1]  # most recent

        boxjs_results = {
            "iocs": [],
            "urls": [],
            "output_dir": results_dir,
        }

        # Parse IOC.json
        ioc_path = os.path.join(results_dir, "IOC.json")
        if os.path.exists(ioc_path):
            try:
                with open(ioc_path, "r", encoding="utf-8") as f:
                    boxjs_results["iocs"] = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to parse IOC.json: {e}")

        # Parse urls.json
        urls_path = os.path.join(results_dir, "urls.json")
        if os.path.exists(urls_path):
            try:
                with open(urls_path, "r", encoding="utf-8") as f:
                    boxjs_results["urls"] = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to parse urls.json: {e}")

        return boxjs_results

    def extract_and_store_data_urls(self, url_list):
        data_url_entries = []
        kept_urls = []
        for url in url_list:
            match = data_url_pattern.match(url.strip())
            if not match:
                kept_urls.append(url)
                continue

            claimed_mime = match.group(1) or "text/plain"
            rest_params = match.group(2) or ""
            data_part = match.group(3)

            is_base64 = "base64" in rest_params.lower()

            if is_base64:
                try:
                    raw_bytes = base64.b64decode(data_part, validate=True)
                except Exception:
                    raw_bytes = data_part.encode("utf-8", errors="replace")
            else:
                from urllib.parse import unquote

                decoded_str = unquote(data_part)
                raw_bytes = decoded_str.encode("utf-8", errors="replace")

            actual_mime = magic.from_buffer(raw_bytes, mime=True)
            file_type = magic.from_buffer(raw_bytes)
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
            sha1_hash = hashlib.sha1(raw_bytes).hexdigest()
            md5_hash = hashlib.md5(raw_bytes).hexdigest()
            out_filename = f"{sha256_hash}.bin"
            out_path = os.path.join(self.output_dir, out_filename)
            with open(out_path, "wb") as out_f:
                out_f.write(raw_bytes)

            ahash = dhash = phash = None
            if (not self.disable_image_hashes) and actual_mime.startswith("image/"):
                try:
                    img = Image.open(out_path)
                    ahash = str(imagehash.average_hash(img))
                    dhash = str(imagehash.dhash(img))
                    phash = str(imagehash.phash(img))
                    chash = str(imagehash.colorhash(img, binbits=6))
                    img.close()
                except Exception as e:
                    logger.warning(f"Error calculating image hashes for {out_path}: {e}")

            entry = {
                "claimed_mime": claimed_mime,
                "actual_mime": actual_mime,
                "file_type": file_type,
                "is_base64": is_base64,
                "file_path": out_path,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
                "md5": md5_hash,
                "size": len(raw_bytes),
            }
            if ahash or dhash or phash:
                entry["image_hashes"] = {
                    "ahash": ahash,
                    "dhash": dhash,
                    "phash": phash,
                    "chash": chash,
                }

            data_url_entries.append(entry)

        return data_url_entries, kept_urls
