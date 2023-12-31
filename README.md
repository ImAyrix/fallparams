<h4 align="center"> Find all parameters and generate a custom target parameter wordlist  </h4>
<p align="center">
  <a href="#installation">Install</a> •
  <a href="#usage-parameters">Usage Parameters</a> •
  <a href="#preview">Preview</a> •
  <a href="#contributing">Contributing</a> •
  <a href="https://t.me/ImAyrix">Contact me</a>
</p>

---

FallParams meticulously analyzes website links to craft targeted parameter wordlists, fueling efficient bug hunting and vulnerability discovery. It accepts a list of URLs as input, expertly scanning their source code to uncover valuable parameters. For comprehensive exploration, unleash its crawling capabilities to unearth hidden parameters within linked pages. FallParams seamlessly navigates dynamic content with headless browser support, ensuring thorough parameter extraction across all website facets.

## Installation

```
go install github.com/ImAyrix/fallparams@latest
```

## Usage Parameters
```
fallparams -h
```

This will display help for the tool. Here are all the switches it supports.
```
Find All Parameters

Usage:
  fallparams [flags]

Flags:
INPUT:
   -u, -url string  Input [Filename | URL]

RATE-LIMIT:
   -t, -thread int  Number Of Thread [Number] (default 1)
   -s, -sleep int   Time for sleep after sending each request

CONFIGURATIONS:
   -c, -crawl                 Crawl pages to extract their parameters
   -d, -depth int             maximum depth to crawl (default 2)
   -hc, -headless-crawl       Enable headless hybrid crawling (experimental)
   -hp, -headless-parameter   Discover parameters with headless browser
   -H, -header "Name: Value"  Header "Name: Value", separated by colon. Multiple -H flags are accepted.

OUTPUT:
   -o, -output string   File to write output to (default "parameters.txt")
   -l, -max-length int  Maximum length of words (default 30)

```

## Preview

![Screenshot from 2023-12-31 22-08-57](https://github.com/ImAyrix/fallparams/assets/89543912/8e798c74-de9b-43f4-b1b3-9bef78170068)

## Contributing

Contributions to Fallparams are welcome! If you find any issues or have suggestions for improvements, we appreciate your contribution. Your feedback helps us make Fallparams better for everyone.
