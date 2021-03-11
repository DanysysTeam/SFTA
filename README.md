# SFTA

[![Latest Version](https://img.shields.io/badge/Latest-v1.3.1-green.svg)]()
[![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)]()
[![Made with Love](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red.svg?colorB=11a9f7)]()


Set File Type Association Default Application Command Line Windows 10


## Features
* Set File Type Association.
* Set Protocol Association.
* Get File Type Association.
* List File Type Association.
* Register Application.
* Unregister Application.

## Usage
##### Type -h, --help command for information

## Basic Usage

##### Set Acrobat Reader DC as Default .pdf reader:
```batch
SFTA.exe AcroExch.Document.DC .pdf

```

##### Set Sumatra PDF as Default .pdf reader:
```batch
SFTA.exe Applications\SumatraPDF.exe .pdf

```


##### Set Google Chrome as Default for http Protocol:
```batch
SFTA.exe ChromeHTML http

```


## Release History
See [CHANGELOG.md](CHANGELOG.md)


<!-- ## Acknowledgments & Credits -->


## License

Usage is provided under the [MIT](https://choosealicense.com/licenses/mit/) License.

Copyright © 2021, [Danysys.](https://www.danysys.com)