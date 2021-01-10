# lcsync - Librecast Multicast Sync Tool

Work in progress.

Librecast file and data syncing tool.

Compare data with merkle trees, sync via multicast.

## Usage

Syncing local files:

`lcsync source destination`

lcsync assumes source and destination are network addresses unless told
otherwise.  To refer to a local destination, you must specify the path.  For files in the
local directory, prefix them with ./

Fetch remote file, save as localfile in current directory:

`lcsync remote ./localfile`

Serve local file:

`lcsync /path/to/localfile`

Serve local file "./somefile" as alias "easy2type":

`lcsync ./somefile easy2type`

and fetch that file:

`lcsync easy2type`

## License

GPLv3+
