# Mass XSS Scanner (MXS)

An advanced XSS scanner that utilizes asynchronous requests to scan a large number of URLs quickly and efficiently.

## Features

- Low CPU usage: Utilizes asynchronous requests to scan, consuming less CPU than traditional scanners.
- Memory efficient: Efficiently handles large wordlists.
- Fast: Can scan a large wordlist in a matter of seconds.
- Low false positives: Employs a polyglot XSS payload to minimize false positives.

## Demo Video

![](https://cdn.sarperavci.com/pvYeTsib/tewXFr.gif)

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python3 MXS.py -i <input_file> -c <concurrency> -o <output_file> -t <timeout>
```

Example:

```bash
python3 MXS.py -i wordlist.txt -c 1500 -o results.txt -t 15
```

This will scan the `wordlist.txt` file with a concurrency of 1500, a timeout of 15 seconds, and save the results to `results.txt`.

### Options

- `-i` or `--input`: Specify the input file containing URLs for scanning.
- `-c` or `--concurrency`: Set the number of concurrent requests to be made.
- `-o` or `--output`: Define the output file for storing the results.
- `-t` or `--timeout`: Set the timeout duration (in seconds) for each request.
- `-p` or `--payload`: Specify a file that contains a custom payload.
- `-x` or `--hidden`: Suppress domain names in the terminal output.
- `-h` or `--help`: Display the help message.

## What's Next?

- Add support for multiple payloads.
- Improve the concurrency system.

## Notes

If you are experiencing issues with concurrency, you can try reducing the number of concurrent requests or increasing the timeout. For example, with a download speed of 300 Mbps, using a concurrency of 1500 and a 15-second timeout typically yields optimal results

## Contributing

If you want to contribute to this project, feel free to fork it and submit a pull request. It will be reviewed as soon as possible and merged if it is a good fit for the project.