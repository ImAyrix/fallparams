<h4 align="center"> Find all parameters and generate a custom target parameter wordlist  </h4>
<p align="center">
  <a href="#installation">Install</a> •
  <a href="#usage-parameters">Usage Parameters</a> •
  <a href="#preview">Preview</a> •
  <a href="#full-guide">Full Guide</a> •
  <a href="#contributing">Contributing</a> •
  <a href="https://t.me/ImAyrix">Contact me</a>
</p>

---

FallParams meticulously analyzes website links to craft targeted parameter wordlists, fueling efficient bug hunting and vulnerability discovery. It accepts a list of URLs as input, expertly scanning their source code to uncover valuable parameters. For comprehensive exploration, unleash its crawling capabilities to unearth hidden parameters within linked pages. FallParams seamlessly navigates dynamic content with headless browser support, ensuring thorough parameter extraction across all website facets.

## Preview

![Fallparams Demo](https://github.com/ImAyrix/fallparams/assets/89543912/ad65c1df-fe40-4dd8-a069-4e352029bc21)

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
   -u, -url string          Input [Filename | URL]
   -dir, -directory string  Stored requests/responses files directory path (offline)

RATE-LIMIT:
   -t, -thread int  Number of Threads [Number] (default 1)
   -rd, -delay int  Request delay between each request in seconds

CONFIGURATIONS:
   -c, -crawl                  Crawl pages to extract their parameters
   -d, -depth int              maximum depth to crawl (default 2)
   -ct, -crawl-duration value  maximum duration to crawl the target
   -hl, -headless              Discover parameters with headless browser
   -H, -header "Name: Value"   Header "Name: Value", separated by colon. Multiple -H flags are accepted.

OUTPUT:
   -o, -output string    File to write output to (default "parameters.txt")
   -xl, -max-length int  Maximum length of words (default 30)
   -nl, -min-length int  Minimum length of words

UPDATE:
   -duc, -disable-update-check  Disable automatic fallparams update check

```

## Full Guide
### Troubleshooting Installation and Execution
If you encounter problems installing and running Fallparams, ensure that the version of Go installed on your system is the latest. Additionally, verify that you have GCC installed.

### Start
To create a parameter wordlist suitable for the page you are working on, simply provide the page link to fallparams.

```bash
fallparams -u "https://target.tld/page"
```
If you have many URLs for which you want to create a parameter wordlist, save all your URLs in a file and then provide the file name to fallparams.
```bash
fallparams -u "/path/to/file.txt"
```

### Custom Header
The URLs you provide might require a specific header to open or may return a different response based on the header. For example, the user information change section on most sites requires an authentication cookie. Using the following method, you can set as many headers as needed for sending the requests.
```bash
fallparams -u "https://target.tld/profile/edit" -H "Cookie: auth=token" -H "Role: Admin"
```

### Headless
Many modern websites utilize JavaScript to dynamically generate their DOM, leading to variations between HTTP responses and browser DOM. To bridge this disparity, employing the headless switch can be advantageous.
```bash
fallparams -u "https://target.tld/page" -headless
```

### More Parameters
One of the great features of fallparams is its ability to use [Katana](https://github.com/projectdiscovery/katana) to crawl the links provided as input, resulting in more links and eventually creating a comprehensive parameter wordlist.
```bash
fallparams -u "https://target.tld/page" -crawl
```

### Offline Mode
If you've already run Katana or any other tool and stored the answer or source pages in files, simply move all the files into one directory. Then provide the directory path to fallparams. In this case, fallparams itself will not send a request and will use the contents of your files.
```bash
fallparams -dir "/path/to/directory"
```

### Output
To enhance the quality of your parameter wordlist, it's crucial to filter out noisy or irrelevant words that may enter during creation. One effective way to achieve this is by setting a specific character limit for each parameter.
```bash
fallparams -u "https://target.tld/page" -max-length 30
```
You can also specify the minimum number of characters for each parameter.
```bash
fallparams -u "https://target.tld/page" -min-length 3
```
By default, the generated parameter wordlist is saved in the parameters.txt file. However, you can customize the name and path of the output file as needed.
```bash
fallparams -u "https://target.tld/page" -output "custom_name.txt"
```
## Contributing

Contributions to Fallparams are welcome! If you find any issues or have suggestions for improvements, we appreciate your contribution. Your feedback helps us make Fallparams better for everyone.
