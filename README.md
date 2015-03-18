io_peer_mem: Peer Memory Client for IO/PFN/MIXEDMAP memory.
===========================================================

This kernel module is a client for Yishai Hadas's IB Peer Memory patch
set [1]. The patch allows RDMA transfers with various types of memory
like mmaped devices (that create PFN mappings) and mmaped files from
DAX filesystems, such as those that reside on NVRAM devices (though
these require the kernel patch in [2]).

This can be tested with either donard_rdma [3] or a patched version of
the IB perftest toolset [4].

Some examples include:

* donard_rdma_server -m /mnt/dax_fs/test.dat
* ib_read_bw -n 20 -R -a --mmap=/mnt/dax_fs/test.dat
* ib_read_bw -n 20 -R -a --mmap=/dev/pfn_mmapable_char_dev
* ib_read_bw -n 20 -R -a --mmap=/sys/bus/pci/devices/0000\:03\:00.0/resource4_wc



---------------------------------------

[1] http://comments.gmane.org/gmane.linux.drivers.rdma/21849

[2] https://github.com/sbates130272/linux-donard/commit/e50a659f074c285968a7404c0da2295093579509

[3] https://github.com/sbates130272/donard_rdma

[4] https://github.com/lsgunth/perftest
