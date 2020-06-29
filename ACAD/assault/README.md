# assault, (webserver attack/analysis boi)

A simple CLI load testing tool.

## Installation

Install using `pip`:

```
$ pip install assault
```

## Usage

The simplest usage of `assault` requires only a URL to test against and 500 requests synchronously (one at a time). This is what it would look like:

```
$ assault https://example.com
.... Done!
--- Results ---
Successful requests     500
Slowest                 0.010s
Fastest                 0.001s
Average                 0.003s
Total time              0.620s
Requests Per Minute     48360
Requests Per Second     806
```

If we want to add concurrency, we'll use the `-c` option, and we can use the `-r` option to specify how many requests that we'd like to make:

```
$ assault -r 3000 -c 10 https://example.com
.... Done!
--- Results ---
Successful requests     3000
Slowest                 0.010s
Fastest                 0.001s
Average                 0.003s
Total time              2.400s
Requests Per Minute     90000
Requests Per Second     1250
```

If you'd like to see these results in JSON format, you can use the `-j` option with a path to a JSON file:

```
$ assault -r 3000 -c 10 -j output.json https://example.com
.... Done!
```

## Development

For working on `assult`, you'll need to have Python >= 3.7 (because we'll use `asyncio`) and [`pipenv`][1] installed. With those installed, run the following command to create a virtualenv for the project and fetch the dependencies:

```
$ pipenv install --dev
...
```

Next, activate the virtualenv and get to work:

```
$ pipenv shell
...
(assault) $
```

[1]: https://docs.pipenv.org/en/latest/
