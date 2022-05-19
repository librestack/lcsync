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

To sync remote files, each file is split into blocks and a merkle tree is built
by hashing the blocks using BLAKE2S. On the sending/server side, this tree is
sent on Librecast Channel (IPv6 multicast group) that is formed from the hash of
the filename.  The receiver/client joins this channel, and receives the tree.
If the client already has some data to compare, it builds a merkle tree of the
destination file and uses this to quickly compare which blocks differ. It builds
a bitmap with this information, and then joins the Channel(s) for the block(s)
required which are sent by the server.

There is no unicast communication with the server. There are no requests sent,
and the server can sit behind a firewall which is completely closed to inbound
TCP and UDP traffic.  Instead, the server listens on a raw socket for Multicast
Listener Discovery (MLD2) reports. It compares any MLD multicast group JOINs
against the index it built on startup and finds matches for file (tree) and
blocks. In this way, the server only sends data when at least one client is
subscribed.  If further clients want to download the data, the server need take
no further action.  Thus, the load on the server does not change at all,
regardless of whether there is one client or a billion.

*lcsync* uses an experimental form of MLD triggering.  Instead of using
linked-lists for tracking multicast groups, as the Linux kernel does, I wanted
to test something more scalable. There can potentially be 2^112 multicast groups
in IPv6, so beyond a certain point the O(n) search on a linked-list does not
scale. lcsync uses SIMD (CPU vector operations) to implement counted bloom
filters, as well as what I'm calling a "bloom timer", which lets us track active
multicast groups in O(1) constant time.  This works, but has the drawback that
even for 0 active groups, CPU usage is constant. The size of the bloom filters
can be tuned depending on the expected number of simultaneous groups.  It really
only makes sense to use this approach for a large number or groups. For smaller
numbers of groups, a binary tree or even a linked-list such as the Linux kernel
uses is more appropriate.  The option to use a simpler structure will be added
in a future release.

## Usage

Syncing local files:

`lcsync source destination`

lcsync assumes source and destination are network addresses unless told
otherwise.  To refer to a local destination, you must specify the path.  For files in the
local directory, prefix them with ./

Fetch remote file, save as localfile in current directory:

`lcsync remote ./localfile`

or

`lcsync share/dir/file ./localfile`

The following command fetches share/dir/file from the network and saves it as `/tmp/oot/file`:

`lcsync share/dir/file /tmp/oot/`

Serve local file:

`lcsync /path/to/localfile`

Serve local directory files. lcsync will index and serve all files under the
source directory:

`lcsync /path/to/files/`

## Options

--blocksz integer
: hash file in /integer/ sized chunks

-c / --channels integer
: maximum number of channels (multicast groups) to use when syncing

--delay integer
: delay between packeets in microseconds

-n / --dry-run
: don't copy any data

--hex
: dump file hashes in hex

--loglevel integer
: set loglevel

--mld
: use MLD triggering

-q / --quiet
: shhh - we're hunting wabbits

-v / --verbose
: increase verbosity

-a / --archive
: set archive options [presently only -p]

-p / --perms
: set file permissions on destination

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
