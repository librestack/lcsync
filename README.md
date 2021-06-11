# lcsync - Librecast Multicast Sync Tool

Work in progress.

Librecast file and data syncing tool.

Compare data with merkle trees, sync via multicast.

## File Syncing

Data is compared by generating a merkle tree using blake2s hashes.

For local file syncing we walk the trees and compare the hashes to find which
data blocks are different.

When sending across a network, the source (sender) chooses how many multicast
groups (channels) to use as a power of 2 and divides the data chunks to send
according to the matching level of the merkle tree, sending data for that
portion of the tree on a channel created from the appropriate node hash.

The merkle tree data is also sent on a loop on the channel which matches the
root hash of the file.  NB: if only one data channel is in use, this is going to
conflict, so we hash in an extra flag to mark it as tree data when forming the
channel hash.

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

## Testing

`sudo make net-setup` (`sudo make net-teardown` when finished)

```sudo ip netns exec vnet0 sudo -u `id -un` /bin/bash```

Now we can run `make test` and `sudo make cap` in our test namespace.

## License

GPLv3+
