# violet_svg/sli.py
import os
import sys
import json
import argparse
import logging
import traceback

from .violet_svg import SVGAnalyzer

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="SLI interface for violet_svg analysis.")
    parser.add_argument("-i", "--input", required=True, help="Path to input SVG file")
    parser.add_argument("-o", "--output", required=True, help="Name of output JSON file")
    parser.add_argument("-d", "--dir", required=True, help="Directory to store output & extracted payloads")
    parser.add_argument("--disable-image-hashes", action="store_true", help="Skip image hashing for data: images")
    parser.add_argument("--raw", action="store_true", help="Include raw SVG content in the JSON output")
    parser.add_argument("--boxjs-path", default=None, help="Path to box-js binary to automatically run box-js on reconstructed scripts")
    parser.add_argument("--boxjs-timeout", type=int, default=20, help="Timeout in seconds for box-js script execution (default: 20)")
    args = parser.parse_args()
    print(
        """
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
      """
    )
    # Instantiate the analyzer
    analyzer = SVGAnalyzer()
    results = {}
    try:
        results = analyzer.analyze_file(
            input_path=args.input, output_dir=args.dir, disable_image_hashes=args.disable_image_hashes, raw=args.raw,
            boxjs_path=args.boxjs_path,
            boxjs_timeout=args.boxjs_timeout
        )
    except Exception as e:
        logger.error(f"An error occurred during analysis: {e}")
        logger.error("{}".format(traceback.format_exc()))
        sys.exit(1)

    # Write the JSON results
    os.makedirs(args.dir, exist_ok=True)
    output_path = os.path.join(args.dir, args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Analysis complete. Results written to: {output_path}")


if __name__ == "__main__":
    main()
