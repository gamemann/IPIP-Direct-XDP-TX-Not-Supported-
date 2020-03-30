#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>

#include <linux/if_link.h>

static uint8_t cont = 1;
static int map_fd;
extern int errno;

void signHdl(int tmp)
{
    cont = 0;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

	fd = bpf_map__fd(map);

    out:
	    return fd;
}


int load_bpf_object_file__simple(const char *filename)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);

    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d\n", filename, strerror(-err), err);

        return -1;
    }

    map_fd = find_map_fd(obj, "interface_map");

    return first_prog_fd;
}

static int xdp_detach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int xdp_attach(int ifindex, uint32_t *xdp_flags, int prog_fd)
{
    int err;
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, *xdp_flags);

    if (err == -EEXIST && !(*xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        
        uint32_t oldflags = *xdp_flags;

        *xdp_flags &= ~XDP_FLAGS_MODES;
        *xdp_flags |= (oldflags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifindex, -1, *xdp_flags);

        if (!err)
        {
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, oldflags);
        }
    }

    // Check for no XDP-Native support.
    if (err)
    {
        fprintf(stdout, "XDP-Native may not be supported with this NIC. Using SKB instead.\n");

        // Remove DRV Mode flag.
        if (*xdp_flags & XDP_FLAGS_DRV_MODE)
        {
            *xdp_flags &= ~XDP_FLAGS_DRV_MODE;
        }

        // Add SKB Mode flag.
        if (!(*xdp_flags & XDP_FLAGS_SKB_MODE))
        {
            *xdp_flags |= XDP_FLAGS_SKB_MODE;
        }

        err = bpf_set_link_xdp_fd(ifindex, prog_fd, *xdp_flags);
    }

    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. Error => %s. Error Num => %d. IfIndex => %d.\n", strerror(-err), -err, ifindex);

        switch(-err)
        {
            case EBUSY:

            case EEXIST:
            {
                xdp_detach(ifindex, *xdp_flags);
                fprintf(stderr, "Additional: XDP already loaded on device.\n");
                break;
            }

            case EOPNOTSUPP:
                fprintf(stderr, "Additional: XDP-native nor SKB not supported? Not sure how that's possible.\n");

                break;

            default:
                break;
        }

        return -1;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Interface>\n", argv[0]);

        exit(1);
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }


    int prog_fd, err;
    int ifindex;
    uint32_t xdp_flags;
    char fileName[] = "IPIPDirect_kern.o";

    xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    ifindex = if_nametoindex(argv[1]);

    if (ifindex <= 0)
    {
        fprintf(stderr, "Error loading interface (%s).\n", argv[1]);

        exit(1);
    }

    prog_fd = load_bpf_object_file__simple(fileName);

    if (prog_fd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", fileName);

        exit(1);
    }

    err = xdp_attach(ifindex, &xdp_flags, prog_fd);

    if (err)
    {
        exit(err);
    }

    // Get IP address of interface.
    int sockfd;
    char *ip;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        fprintf(stderr, "Error creating socket to get IP address. Error => %s. Error Num => %d. Attempting to use command line.\n", strerror(errno), errno);

        if (argc < 3)
        {
            fprintf(stderr, "No IP specified.\n");
            
            exit(1);
        }

        ip = argv[2];
    }

    if (sockfd)
    {
        ifr.ifr_addr.sa_family = AF_INET;

        strcpy(ifr.ifr_name, argv[1]);

        if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
        {
            fprintf(stderr, "Error using ioctl(). Error => %s. Error Num => %d. Resorting to command line.\n", strerror(errno), errno);

            if (argc < 3)
            {
                fprintf(stderr, "No IP specified.\n");
                
                exit(1);
            }

            ip = argv[2];
        }
        else
        {
            ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
        }
    }

    close(sockfd);

    // Add to BPF map.
    uint32_t ipAddr = inet_addr(ip);
    uint32_t key = 0;
    bpf_map_update_elem(map_fd, &key, &ipAddr, BPF_ANY);

    signal(SIGINT, signHdl);

    fprintf(stdout, "Starting IPIP Direct XDP program. Interface address => %s.\n", ip);

    while (cont)
    {
        sleep(1);
    }

    fprintf(stdout, "Cleaning up...\n");

    err = xdp_detach(ifindex, xdp_flags);

    if (err)
    {
        exit(err);
    }

    exit(0);
}