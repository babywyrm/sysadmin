// https://gist.github.com/giannitedesco/1034470
//
//

/* Fast grep thing, using boyer-moore delta-1 heuristic */
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

static const uint8_t *bm_find(const uint8_t *n, size_t nlen,
			const uint8_t *hs, size_t hlen,
			int *skip)
{
	int skip_stride, shift_stride, p_idx;
	int b_idx;

	/* Do the search */
	for(b_idx = nlen; b_idx <= hlen; ) {
		p_idx = nlen;

		while(hs[--b_idx] == n[--p_idx]) {
			if (b_idx < 0)
				return NULL;
			if (p_idx == 0)
				return hs + b_idx;
		}

		skip_stride = skip[hs[b_idx]];
		shift_stride = (nlen - p_idx) + 1;

		/* micro-optimised max() function */
		b_idx += ( (skip_stride - shift_stride) > 0 )
			? skip_stride : shift_stride;
	}

	return NULL;
}

static void bm_skip(const uint8_t *x, size_t plen, int *skip)
{
	int *sptr = &skip[0x100];

	while( sptr-- != skip )
		*sptr = plen + 1;

	while(plen != 0)
		skip[*x++] = plen--;
}

static const uint8_t *mapfile(int fd, size_t *len)
{
	struct stat st;
	const uint8_t *map;

	*len = 0;

	if ( fstat(fd, &st) )
		return NULL;

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if ( map == MAP_FAILED )
		return NULL;

	*len = st.st_size;
	return map;
}

int main(int argc, char **argv)
{
	const uint8_t *haystack, *needle, *result, *ptr;
	const char *hfn, *nfn;
	int hfd, nfd, depth;
	size_t hlen, nlen, plen;
	int skip[0x100];


	if ( argc != 3 ) {
		fprintf(stderr, "%s: <haystack> <needle>\n", argv[0]);
		return EXIT_FAILURE;
	}

	hfn = argv[1];
	nfn = argv[2];

	hfd = open(hfn, O_RDONLY);
	if ( hfd < 0 ) {
		fprintf(stderr, "%s: %s: open(): %s\n",
			argv[0], hfn, strerror(errno));
		return EXIT_FAILURE;
	}

	nfd = open(nfn, O_RDONLY);
	if ( nfd < 0 ) {
		fprintf(stderr, "%s: %s: open(): %s\n",
			argv[0], nfn, strerror(errno));
		return EXIT_FAILURE;
	}

	haystack = mapfile(hfd, &hlen);
	if ( haystack == NULL ) {
		fprintf(stderr, "%s: %s: mapfile(): %s\n",
			argv[0], hfn, strerror(errno));
		return EXIT_FAILURE;
	}

	needle = mapfile(nfd, &nlen);
	if ( needle == NULL ) {
		fprintf(stderr, "%s: %s: mapfile(): %s\n",
			argv[0], nfn, strerror(errno));
		return EXIT_FAILURE;
	}

	bm_skip(needle, nlen, skip);

	ptr = haystack;
	plen = hlen;

again:
	result = bm_find(needle, nlen, ptr, plen, skip);
	if ( result == NULL )
		return EXIT_SUCCESS;

	depth = result - haystack;

	assert((depth + nlen) <= hlen);
	assert(memcmp(result, needle, nlen) == 0);

	printf("Found @ 0x%.8x / %u\n", depth, depth);

	depth  = result- ptr;
	depth += nlen;
	ptr += depth;
	plen -= depth;
	goto again;
}
