# lcsync - Librecast Multicast Sync Tool

<a href="https://librecast.net/lcsync.html"><img height="150" align="left" src="https://librecast.net/media/lcsync.svg" alt="lcsync logo"></a>

<a href="https://opensource.org"><img height="150" align="right" src="https://opensource.org/files/OSIApprovedCropped.png" alt="Open Source Initiative Approved License logo"></a>


Work in progress.

Librecast file and data syncing tool.

https://librecast.net/lcsync.html

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

GPLv2 or (at your option) GPLv3

<hr />

<p class="bigbreak">
This project was funded through the <a href="https://nlnet.nl/discovery"> NGI0 Discovery </a> Fund, a fund established by NLnet with financial support from the European
Commission's <a href="https://ngi.eu">Next Generation Internet</a> programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825322. *Applications are still open, you can <a href="https://nlnet.nl/propose">apply today</a>*
</p>

<p>
  <a href="https://nlnet.nl/project/LibrecastLive/">
      <img width="250" src="https://nlnet.nl/logo/banner.png" alt="Logo NLnet: abstract logo of four people seen from above" class="logocenter" />
  </a>
  <a href="https://ngi.eu/">
      <img width="250" align="right" src="https://nlnet.nl/image/logos/NGI0_tag.png" alt="Logo NGI Zero: letterlogo shaped like a tag" class="logocenter" />
  </a>
</p>
